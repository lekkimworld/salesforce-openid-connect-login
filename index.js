const express = require('express')
const session = require('express-session')
const fetch = require('node-fetch')
const FormData = require('form-data')
const nJwt = require('njwt')
const njwk = require('node-jwk')

const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET
const OAUTH_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI
const KID_OVERRIDE = process.env.KID_OVERRIDE
const SF_LOGIN_URL = process.env.SF_LOGIN_URL || 'https://login.salesforce.com'

const app = express()

// json formatting
app.set('json replacer', undefined)
app.set('json spaces', 2)

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true, 
    cookie: { maxAge: 60000 }
}))

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
        return verifyIDToken(idtoken)

    }).then(verifyResult => {
        req.session.user = verifyResult
        req.session.save()
        return res.redirect('/')

    }).catch(err => {
        console.log(`Error: ${err.message}`, err)
        return res.status(500).send(err.message).end()

    })
})

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

app.get('/json', (req, res) => {
    res.json(req.session.user).end()
})
app.get('/', (req, res) => {
    const user = req.session.user
    const response = `<html><head><title>${user.body.name}</title></head><body>Hello ${user.body.name}!</body></html>\n`
    res.send(response).end()
})

// listen
app.listen(process.env.PORT || 3000)

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
            resolve(verifyResult)

        }).catch(err => {
            return reject(err)
        })
    })
}