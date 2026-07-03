'use strict'

const mongoose = require('mongoose')
const Schema = mongoose.Schema

const EnterpriseKeySchema = new Schema({
    apiKey: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    apiSecret: {
        type: String,
        required: true
    },
    enterpriseName: {
        type: String,
        required: true
    }
}, { timestamps: true })

module.exports = mongoose.model('EnterpriseKey', EnterpriseKeySchema)
