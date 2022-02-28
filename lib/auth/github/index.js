'use strict'

const Router = require('express').Router
const passport = require('passport')
const GithubStrategy = require('passport-github').Strategy
const config = require('../../config')
const response = require('../../response')
const { setReturnToFromReferer } = require('../utils')
const { URL } = require('url')
const { InternalOAuthError } = require('passport-oauth2')
const githubAuth = (module.exports = Router())
const axios = require('axios')
const models = require('../../models')
const logger = require('../../logger')

function githubUrl (path) {
  return (
    config.github.enterpriseURL &&
    new URL(path, config.github.enterpriseURL).toString()
  )
}

/**
 * fork from ../util.js passsportGeneralCallback
 * githubユーザーのwhitelist検証を追加したコールバック
 */
async function passportCustomGithubCallback (
  accessToken,
  refreshToken,
  profile,
  done
) {
  const res = await axios.get(
    'https://gist.githubusercontent.com/magcho/bebda0c4dd507d30eefae588b2b00d3c/raw/codimd-permit.json'
  )
  const limitConfig = res.data

  if (!limitConfig.permitUser.some((user) => user === profile.displayName)) {
    return done(InternalOAuthError(`User not whitelisted`))
  }

  var stringifiedProfile = JSON.stringify(profile)
  models.User.findOrCreate({
    where: {
      profileid: profile.id.toString()
    },
    defaults: {
      profile: stringifiedProfile,
      accessToken: accessToken,
      refreshToken: refreshToken
    }
  })
    .spread(function (user, created) {
      if (user) {
        var needSave = false
        if (user.profile !== stringifiedProfile) {
          user.profile = stringifiedProfile
          needSave = true
        }
        if (user.accessToken !== accessToken) {
          user.accessToken = accessToken
          needSave = true
        }
        if (user.refreshToken !== refreshToken) {
          user.refreshToken = refreshToken
          needSave = true
        }
        if (needSave) {
          user.save().then(function () {
            if (config.debug) {
              logger.info('user login: ' + user.id)
            }
            return done(null, user)
          })
        } else {
          if (config.debug) {
            logger.info('user login: ' + user.id)
          }
          return done(null, user)
        }
      }
    })
    .catch(function (err) {
      logger.error('auth callback failed: ' + err)
      return done(err, null)
    })
}

passport.use(
  new GithubStrategy(
    {
      clientID: config.github.clientID,
      clientSecret: config.github.clientSecret,
      callbackURL: config.serverURL + '/auth/github/callback',
      authorizationURL: githubUrl('login/oauth/authorize'),
      tokenURL: githubUrl('login/oauth/access_token'),
      userProfileURL: githubUrl('api/v3/user')
    },
    passportCustomGithubCallback
  )
)

githubAuth.get('/auth/github', function (req, res, next) {
  setReturnToFromReferer(req)
  passport.authenticate('github')(req, res, next)
})

// github auth callback
githubAuth.get(
  '/auth/github/callback',
  passport.authenticate('github', {
    successReturnToOrRedirect: config.serverURL + '/',
    failureRedirect: config.serverURL + '/'
  })
)

// github callback actions
githubAuth.get('/auth/github/callback/:noteId/:action', response.githubActions)
