const express = require('express')
const session = require('express-session')
const fetch = require('node-fetch')
const FormData = require('form-data')
const nJwt = require('njwt')
const njwk = require('node-jwk')
const uuid = require('uuid/v4')

// configuration from environment
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET
const OAUTH_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI
const KID_OVERRIDE = process.env.KID_OVERRIDE
const SF_LOGIN_URL = process.env.SF_LOGIN_URL || 'https://login.salesforce.com'

const app = express()

// json formatting
app.set('json replacer', undefined)
app.set('json spaces', 2)

// configure our session
app.use(session({
    secret: uuid(),
    resave: false,
    saveUninitialized: true, 
    cookie: {
        maxAge: 5 * 60 * 1000 // 5 minutes
    }
}))

/**
 * Specific route for OAuth callback.
 */
app.get('/oauth/callback', (req, res) => {
    // grab authorization code
    const authcode = req.query.code
    if (!authcode) {
        return res.status(417).send('Expected authorization code').end()
    }
    
    // exchange authcode
    const formdata = new FormData()
    formdata.append('client_id', OAUTH_CLIENT_ID)
    formdata.append('client_secret', OAUTH_CLIENT_SECRET)
    formdata.append('redirect_uri', OAUTH_REDIRECT_URI)
    formdata.append('code', authcode)
    formdata.append('grant_type', 'authorization_code')
    fetch(`${SF_LOGIN_URL}/services/oauth2/token`, {
        method: 'POST',
        body: formdata
    }).then(response => {
        return response.json()
    }).then(payload => {
        // get idtoken out of payload
        const idtoken = payload.id_token

        // we need to verify the token before trusting it
        return Promise.all([Promise.resolve(payload), verifyIDToken(idtoken)])

    }).then(data => {
        const payload = data[0]
        const verifyResult = data[1]

        // grab verify result and payload and store session
        req.session.user = verifyResult
        req.session.payload = payload
        req.session.scopes = payload.scope.split(' ')
        req.session.save()
        console.log(verifyResult)
        console.log(payload)

        // redirect
        return res.redirect('/')

    }).catch(err => {
        console.log(`Error: ${err.message}`, err)
        return res.status(500).send(err.message).end()

    })
})

/**
 * Middleware to always make sure we have authenticated the user.
 */
app.use((req, res, next) => {
    // see if there is a user object in the session
    if (!req.session.user) {
        // there is not - initiate authentication
        return res.redirect(`${SF_LOGIN_URL}/services/oauth2/authorize?client_id=${OAUTH_CLIENT_ID}&redirect_uri=${OAUTH_REDIRECT_URI}&response_type=code&prompt=consent`)
    } else {
        // yay
        return next()
    }
})

/**
 * Route for logout.
 */
app.get('/logout', (req, res) => {
    req.session.destroy()
    res.redirect('/').end()
})

/**
 * Route for HTML response.
 */
app.get('/', (req, res) => {
    // get user and start to build response
    const user = req.session.user
    let response = `<html><head><title>${user.body.name}</title></head><body><h1>Hello ${user.body.name}!</h1><ul>`

    // if we got the web scope we can actually use the access_token to send the user 
    // back to Salesforce (if not the access_token cannot be used for UI login)
    if (req.session.scopes.includes('web')) {
        response += `<li><a href="${req.session.payload.instance_url}/secur/frontdoor.jsp?sid=${req.session.payload.access_token}">Go to Salesforce</a></li>`
    }

    // if we got the api scope we can access Salesforce to get data on behalf of the user
    if (req.session.scopes.includes('api')) {
        response += `<li><a href="/recent">Show last 5 accessed records</a></li>`
    }
    response += `<li><a href="/logout">Logout</a></li>`
    response += `</ul></body></html>\n`
    res.send(response).end()
})

/**
 * Route for 5 most recent records accessed in Salesforce.
 */
app.get('/recent', (req, res) => {
    // verify we have the scope
    if (!req.session.scopes.includes('api')) {
        return res.status(417).send('You do not have this permission').end()
    }

    fetch(`${req.session.payload.instance_url}/services/data/v44.0/recent/?limit=5`, {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${req.session.payload.access_token}`
        }
    })
    .then(response => response.json())
    .then(data => {
        res.json(data)
    }).catch(err => {
        res.status(500).send(`Unable to get data due to error (${err.message})`).end()
    })
})

/**
 * Route for JSON response.
 */
app.get('/json', (req, res) => {
    res.json(req.session.user).end()
})

// listen
app.listen(process.env.PORT || 3000)

/**
 * Method to verify the ID Token we received from Salesforce using the standard 
 * public keys provided by Salesforce.
 * 
 * @param {String} idtoken 
 */
const verifyIDToken = idtoken => {
    return new Promise((resolve, reject) => {
        // get keys from Salesforce
        fetch(`${SF_LOGIN_URL}/id/keys`).then(res => {
            return res.json()
        }).then(keys => {
            // parse jwk keys
            const myKeySet = njwk.JWKSet.fromObject(keys)

            // get header
            const idtoken_parts = idtoken.split('.')

            // parse header
            const header = JSON.parse(Buffer.from(idtoken_parts[0], 'base64').toString('utf8'))
            if (!header.kid || header.typ !== 'JWT' || header.alg !== 'RS256') return rejrect(Error('Missing kid in header or invalid type or algorithm'))

            // get key to use
            const jwkKey = myKeySet.findKeyById(KID_OVERRIDE || header.kid)
            if (!jwkKey) throw Error(`Unable to find key for kid ${header.kid}`)
            return jwkKey.key.toPublicKeyPEM()

        }).then(pem => {
            // verify signature
            const verifyResult = nJwt.verify(idtoken, pem, 'RS256');

            // coming here means we verified the signature - now let's check that we 
            // are the audience meaning it was generated for us
            if (verifyResult.body.aud !== OAUTH_CLIENT_ID) {
                // it wasn't
                return reject(Error('Received JWT wasn\'t generated for us do we wont accept it!'))
            }

            // yay!
            resolve(verifyResult)

        }).catch(err => {
            return reject(err)
        })
    })
}