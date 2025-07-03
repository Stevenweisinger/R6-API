import axios, { AxiosError } from 'axios'
import config from '../configs/config.json'
import { SaveJSONToFile } from '../utilities/file-stream'
import { R6UserResponse } from '../utilities/interfaces/http_interfaces'
import { UbiAppId } from '../utilities/interfaces/enums'

export class UbiLoginManager {
    static instance: UbiLoginManager

    /**
     * Logs into a Ubisoft account twice, once with a V2 appId and once with a
     * V3 appId. Saves both auth tokens + session ID to the `private/auth_token_{VERSION}` files.
     * 
     * Avoid calling this function more than 3 times per hour.
     */
    async Login(): Promise<void> {
        try {
            const tokenV2 = await this.RequestLogin(UbiAppId.v2);
            if (tokenV2) {
                await SaveJSONToFile('private/auth_token_v2.json', tokenV2);
            }

            const tokenV3 = await this.RequestLogin(UbiAppId.v3);
            if (tokenV3) {
                await SaveJSONToFile('private/auth_token_v3.json', tokenV3);
            }
        } catch (error) {
            console.error(error);
        }
    }

    /**
     * Makes an HTTP request to Ubisoft to login to the specified account.
     * 
     * @param appId Ubi-AppId header value.
     * @returns Auth token + sessionId object.
     */
    async RequestLogin(appId: UbiAppId): Promise<(R6UserResponse & { sessionId: string }) | undefined> {
        const credentials = Buffer.from(`${config.ubi_credentials.email}:${config.ubi_credentials.password}`).toString('base64');

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
        };

        try {
            const response = await axios(httpConfig);

            console.log('✅ Ubisoft login response:', {
                data: response.data,
                headers: response.headers
            });

            const sessionId = response.headers['ubi-sessionid'];
            if (!sessionId) {
                throw new Error('Missing Ubi-SessionId header in login response.');
            }

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
                            throw 'Account does not exist.';
                        case 409:
                            throw 'Captcha needed.';
                        case 429:
                            throw 'Too many requests.';
                        default:
                            throw error;
                    }
                }
            }

            throw error;
        }
    }
}
