import axios, { AxiosError } from 'axios'
import fs from 'fs/promises'
import path from 'path'
import config from '../configs/config.json'
import { SaveJSONToFile } from '../utilities/file-stream'
import { R6UserResponse } from '../utilities/interfaces/http_interfaces'
import { UbiAppId } from '../utilities/interfaces/enums'

const TOKEN_PATH_V2 = path.resolve('private/auth_token_v2.json')
const TOKEN_PATH_V3 = path.resolve('private/auth_token_v3.json')

async function loadToken(version: 'v2' | 'v3') {
  const filePath = version === 'v2' ? TOKEN_PATH_V2 : TOKEN_PATH_V3
  try {
    const raw = await fs.readFile(filePath, 'utf8')
    const token = JSON.parse(raw)
    // Check token expiration with 5 minutes buffer
    if (token.expiration && new Date(token.expiration).getTime() > Date.now() + 5 * 60 * 1000) {
      return token
    }
  } catch {
    // File doesn't exist or invalid JSON
  }
  return null
}

async function saveToken(version: 'v2' | 'v3', token: any) {
  const filePath = version === 'v2' ? TOKEN_PATH_V2 : TOKEN_PATH_V3
  await fs.writeFile(filePath, JSON.stringify(token, null, 2), 'utf8')
}

export class UbiLoginManager {
  static instance: UbiLoginManager

  /**
   * Logs into Ubisoft account with V2 and V3 appIds, caches tokens to disk.
   * Avoid calling this more than 3 times per hour to prevent rate limits.
   */
  async Login(): Promise<void> {
    try {
      let tokenV2 = await loadToken('v2')
      if (!tokenV2) {
        tokenV2 = await this.RequestLogin(UbiAppId.v2)
        if (tokenV2) await saveToken('v2', tokenV2)
      }

      let tokenV3 = await loadToken('v3')
      if (!tokenV3) {
        tokenV3 = await this.RequestLogin(UbiAppId.v3)
        if (tokenV3) await saveToken('v3', tokenV3)
      }
    } catch (error) {
      console.error('Login failed:', error)
    }
  }

  /**
   * Sends login request to Ubisoft for the given appId.
   * @param appId Ubi-AppId header value.
   * @returns Auth token + sessionId.
   */
  async RequestLogin(appId: UbiAppId): Promise<(R6UserResponse & { sessionId: string }) | undefined> {
    const credentials = Buffer.from(`${config.ubi_credentials.email}:${config.ubi_credentials.password}`).toString('base64')

    const httpConfig = {
      method: 'POST',
      url: 'https://public-ubiservices.ubi.com/v3/profiles/sessions',
      headers: {
        'User-Agent': config.http.user_agent,
        'Authorization': `Basic ${credentials}`,
        'Ubi-AppId': appId,
        'Connection': 'Keep-Alive',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      data: JSON.stringify({
        rememberMe: true
      })
    }

    try {
      const response = await axios(httpConfig)

      const sessionId = response.headers['ubi-sessionid']
      if (!sessionId) throw new Error('Missing Ubi-SessionId header in login response.')

      return {
        ...response.data,
        sessionId
      }
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError

        if (axiosError.response?.status) {
          switch (axiosError.response?.status) {
            case 401: throw 'Account does not exist.'
            case 409: throw 'Captcha needed.'
            case 429: throw '❌ Too many requests. Rate limit hit.'
            default: throw error
          }
        }
      }
      throw error
    }
  }
}
