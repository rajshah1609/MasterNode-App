'use strict'

require('dotenv').config()

const express = require('express')
const config = require('config')
const bodyParser = require('body-parser')
const validator = require('express-validator')
const path = require('path')
const yaml = require('js-yaml')
const fs = require('fs')
const cors = require('cors')
const swaggerUi = require('swagger-ui-express')
const morgan = require('morgan')
const logger = require('./helpers/logger')
const helmet = require('helmet')
const flash = require('connect-flash')
const fileUpload = require('express-fileupload')
// body parse
const app = express()

// helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ['\'self\''],
            scriptSrc: ['\'self\'', '\'unsafe-inline\'', '\'unsafe-eval\'', 'https://www.google-analytics.com', 'https://www.googletagmanager.com'],
            styleSrc: ['\'self\'', '\'unsafe-inline\''],
            imgSrc: ['\'self\'', 'data:', 'blob:', 'https:', 'http:', 'https://www.google-analytics.com'],
            connectSrc: ['\'self\'', 'https:', 'wss:', 'http:', 'ws:', 'https://www.google-analytics.com'],
            fontSrc: ['\'self\'', 'data:', 'https:'],
            objectSrc: ['\'none\''],
            baseUri: ['\'self\''],
            frameAncestors: ['\'none\''],
            formAction: ['\'self\'']
        }
    },
    frameguard: {
        action: 'deny'
    },
    referrerPolicy: {
        policy: 'strict-origin-when-cross-origin'
    },
    xssFilter: true,
    noSniff: true,
    hidePoweredBy: true
}))

// cors
// app.use(cors({
//     origin: config.get('cors')
// }))

app.use(cors({
    origin: function (origin, callback) {
        const allowedOrigins = [...config.get('cors')]
        const baseUrl = config.get('baseUrl')
        if (baseUrl) {
            const formattedBase = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl
            if (!allowedOrigins.includes(formattedBase)) {
                allowedOrigins.push(formattedBase)
            }
        }

        if (!origin) {
            return callback(null, true)
        }

        if (allowedOrigins.includes(origin)) {
            return callback(null, true)
        }

        return callback(new Error('Not allowed by CORS'))
    }
}))

app.use((err, req, res, next) => {
    if (err && err.message === 'Not allowed by CORS') {
        return res.status(403).json({
            message: 'Blocked by CORS',
            method: req.method,
            url: req.originalUrl,
            origin: req.headers.origin || null
        })
    }

    next(err)
})

app.use(morgan('short', { stream: logger.stream }))

const server = require('http').Server(app)
app.use(flash())
app.use(fileUpload())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(validator({}))

app.use('/build', express.static('build'))
app.use('/app/assets', express.static('app/assets'))
const docs = yaml.safeLoad(fs.readFileSync('./docs/swagger.yml', 'utf8'))
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(docs))

// apis
app.use(require('./apis'))
app.use(require('./middlewares/sitemap'))

// error handler
app.use(require('./middlewares/error'))

app.get('*', function (req, res) {
    let p
    if (process.env.NODE_ENV === 'development') {
        p = path.resolve(__dirname, 'index.html')
    } else {
        p = path.resolve(__dirname, './build', 'index.html')
    }
    return res.sendFile(p)
})

// error handler
app.use(require('./middlewares/error'))

// start server
server.listen(config.get('server.port'), config.get('server.host'), function () {
    const host = server.address().address
    const port = server.address().port
    console.info('Server start at http://%s:%s', host, port)
})

module.exports = app
