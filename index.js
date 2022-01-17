'use strict'

const { randomBytes } = require('crypto')
const fp = require('fastify-plugin')
const helmet = require('helmet')

function helmetPlugin (fastify, options, next) {
  // helmet will throw when any option is explicitly set to "true"
  // using ECMAScript destructuring is a clean workaround as we do not need to alter options
  const { enableCSPNonces, global, ...globalConfiguration } = options

  const isGlobal = typeof global === 'boolean' ? global : true

  // We initialize the `helmet` reply decorator only if it does not already exists
  if (!fastify.hasReplyDecorator('helmet')) {
    fastify.decorateReply('helmet', null)
  }

  // We initialize the `cspNonce` reply decorator only if it does not already exists
  if (!fastify.hasReplyDecorator('cspNonce')) {
    fastify.decorateReply('cspNonce', null)
  }

  // We will add the onRequest helmet middleware functions through the onRoute hook if needed
  fastify.addHook('onRoute', (routeOptions) => {
    if (typeof routeOptions.helmet !== 'undefined') {
      if (typeof routeOptions.helmet === 'object') {
        const { enableCSPNonces: enableRouteCSPNonces, ...helmetRouteConfiguration } = routeOptions.helmet

        // If route helmet options are set they overwrite the global helmet configuration
        const mergedHelmetConfiguration = Object.assign({}, globalConfiguration, helmetRouteConfiguration)

        buildRouteHooks(fastify, mergedHelmetConfiguration, routeOptions, enableRouteCSPNonces)
      } else if (routeOptions.helmet === false) {
        // don't apply any helmet settings but decorate the reply with a fallback to the
        // global helmet options
        buildRouteHooks(fastify, globalConfiguration, routeOptions, false, true)
      } else {
        throw new Error('Unknown value for route helmet configuration')
      }
    } else if (isGlobal) {
      // if the plugin is set globally (meaning that all the routes will be decorated)
      // As the endpoint, does not have a custom helmet configuration, use the global one.
      buildRouteHooks(fastify, globalConfiguration, routeOptions, enableCSPNonces)
    } else {
      // if no options are specified and the plugin is not global, then we still want to decorate
      // the reply in this case
      buildRouteHooks(fastify, globalConfiguration, routeOptions, enableCSPNonces, true)
    }
  })

  next()
}

function buildCSPNonce (fastify, configuration) {
  const cspDirectives = configuration.contentSecurityPolicy
    ? configuration.contentSecurityPolicy.directives
    : helmet.contentSecurityPolicy.getDefaultDirectives()
  const cspReportOnly = configuration.contentSecurityPolicy
    ? configuration.contentSecurityPolicy.reportOnly
    : undefined

  return function (request, reply, payload, next) {
    // prevent object reference: https://github.com/fastify/fastify-helmet/issues/118
    const directives = { ...cspDirectives }

    // push nonce to csp
    // allow both script-src or scriptSrc syntax
    const scriptKey = Array.isArray(directives['script-src']) ? 'script-src' : 'scriptSrc'
    directives[scriptKey] = Array.isArray(directives[scriptKey]) ? [...directives[scriptKey]] : []
    directives[scriptKey].push(`'nonce-${reply.cspNonce === null ? randomBytes(16).toString('hex') : reply.cspNonce.script}'`)
    // allow both style-src or styleSrc syntax
    const styleKey = Array.isArray(directives['style-src']) ? 'style-src' : 'styleSrc'
    directives[styleKey] = Array.isArray(directives[styleKey]) ? [...directives[styleKey]] : []
    directives[styleKey].push(`'nonce-${reply.cspNonce === null ? randomBytes(16).toString('hex') : reply.cspNonce.style}'`)

    const cspMiddleware = helmet.contentSecurityPolicy({ directives, reportOnly: cspReportOnly })
    cspMiddleware(request.raw, reply.raw, next)
  }
}

function buildRouteHooks (fastify, configuration, routeOptions, enableCSPNonces, decorateOnly) {
  if (Array.isArray(routeOptions.onRequest)) {
    routeOptions.onRequest.push(addHelmetReplyDecorator)
  } else if (typeof routeOptions.onRequest === 'function') {
    routeOptions.onRequest = [routeOptions.onRequest, addHelmetReplyDecorator]
  } else {
    routeOptions.onRequest = [addHelmetReplyDecorator]
  }

  const middleware = helmet(configuration)

  function addHelmetReplyDecorator (request, reply, next) {
    // We decorate `reply.helmet` with all helmet middleware functions
    // NB: we allow users to pass a custom helmet options object with a fallback
    // to global helmet configuration.
    reply.helmet = (opts) => opts
      ? helmet(opts)(request.raw, reply.raw)
      : helmet(configuration)(request.raw, reply.raw)

    next()
  }

  if (enableCSPNonces) {
    routeOptions.onRequest.push((request, reply, next) => {
      // create csp nonce
      reply.cspNonce = {
        script: randomBytes(16).toString('hex'),
        style: randomBytes(16).toString('hex')
      }
      next()
    })
  }

  if (decorateOnly) {
    return
  }

  if (Array.isArray(routeOptions.onSend)) {
    routeOptions.onSend.push(onSend)
  } else if (typeof routeOptions.onSend === 'function') {
    routeOptions.onSend = [routeOptions.onSend, onSend]
  } else {
    routeOptions.onSend = [onSend]
  }

  function onSend (request, reply, payload, next) {
    middleware(request.raw, reply.raw, next)
  }

  if (enableCSPNonces) {
    routeOptions.onSend.push(buildCSPNonce(fastify, configuration))
  }
}

module.exports = fp(helmetPlugin, {
  fastify: '3.x',
  name: 'fastify-helmet'
})

module.exports.contentSecurityPolicy = helmet.contentSecurityPolicy
