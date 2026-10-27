/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string

    challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return isUnintendedRedirect(toUrl) })
    challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })

    const ALLOWED_URLS = [
      'https://github.com/juice-shop/juice-shop',
      'https://owasp.org/www-project-juice-shop/'
    ]

    const isSafeRelative = toUrl && toUrl.startsWith('/') && !toUrl.startsWith('//') && !toUrl.startsWith('/\\')
    const isAllowedExternal = ALLOWED_URLS.includes(toUrl)

    if (isSafeRelative || isAllowedExternal) {
      res.redirect(toUrl) // nosemgrep
    } else {
      res.status(403).send('Forbidden - Open Redirect attempt detected')
    }
  }
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !toUrl.startsWith(allowedUrl)
  }
  return unintended
}

