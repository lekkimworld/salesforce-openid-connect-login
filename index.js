const express = require('express')
const session = require('express-session')
const fetch = require('node-fetch')
const FormData = require('form-data')

const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || '3MVG9SemV5D80oBeVT7ei7H08lO.1quM_0aJqwSkse8URATlZ3VMqJFrhNUY94M8R8aQ8sMP1c3Rnm0IFkmrB'
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || '7912037708683740117'
const OAUTH_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI || 'https://httpbin.org/get'
const SF_LOGIN_URL = process.env.SF_LOGIN_URL || 'https://login.salesforce.com'

const app = express()
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true, 
    cookie: { maxAge: 60000 }
}))
app.use((req, res, next) => {
    // see if there is a user object in the session
    if (!req.session.user) {
        // there is not - initiate authentication
        return res.redirect(`${SF_LOGIN_URL}/services/oauth2/authorize?client_id=${OAUTH_CLIENT_ID}&redirect_uri=${OAUTH_REDIRECT_URI}&response_type=code`)
    } else {
        // yay
        return next()
    }
})
app.get('/oauth/callback\?code=:authcode', (req, res) => {
    // grab authorization code
    const authcode = req.params.authcode
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
        req.session.user = payload
        req.session.save()
        return res.redirect('/')
    }).catch(err => {
        console.log(`Error: ${err.message}`, err)
        res.status(500).send(err.message).end()
    })
})

app.get('/*', (req, res) => {
    res.json(req.session.user).end()
})

// listen
app.listen(process.env.PORT || 3000)
