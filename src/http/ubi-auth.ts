import axios, { AxiosError } from 'axios';
import config from '../config';

export type UbiAppId = string;

interface R6UserResponse {
  ticket: string;
  profileId: string;
  userId: string;
  nameOnPlatform: string;
  environment: string;
  expiration: string;
  sessionId: string;
}

class UbiLoginManager {
  private token?: string;
  private sessionId?: string;
  private lastLoginTime?: number;

  private shouldReauthenticate(): boolean {
    // Re-authenticate if more than 30 minutes passed or missing token
    return (
      !this.token ||
      !this.sessionId ||
      !this.lastLoginTime ||
      Date.now() - this.lastLoginTime > 30 * 60 * 1000
    );
  }

  public async getToken(appId: UbiAppId): Promise<{ token: string; sessionId: string }> {
    if (this.shouldReauthenticate()) {
      const result = await this.requestLogin(appId);
      if (!result) throw new Error('Login failed. Cannot retrieve token.');

      this.token = result.ticket;
      this.sessionId = result.sessionId;
      this.lastLoginTime = Date.now();
    }

    return {
      token: this.token!,
      sessionId: this.sessionId!
    };
  }

  private async requestLogin(appId: UbiAppId): Promise<R6UserResponse | undefined> {
    const credentials = Buffer.from(
      `${config.ubi_credentials.email}:${config.ubi_credentials.password}`
    ).toString('base64');

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
      data: JSON.stringify({ rememberMe: true })
    };

    try {
      const response = await axios(httpConfig);

      console.log('✅ Ubisoft login response:', {
        data: response.data,
        headers: response.headers
      });

      const sessionId = response.headers['ubi-sessionid'];
      if (!sessionId) throw new Error('Missing Ubi-SessionId header in login response.');

      return {
        ...response.data,
        sessionId
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError;

        if (axiosError.response?.status) {
          switch (axiosError.response.status) {
            case 401:
              throw new Error('Unauthorized: Incorrect email or password.');
            case 409:
              throw new Error('Conflict: Captcha or other challenge required.');
            case 429:
              throw new Error('Too many requests: Rate limit exceeded.');
            default:
              throw new Error(`Login failed with status ${axiosError.response.status}`);
          }
        }
      }

      throw error;
    }
  }
}

export default new UbiLoginManager();
