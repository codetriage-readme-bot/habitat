// Copyright (c) 2018 Chef Software Inc. and/or applicable contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::Read;

use hab_http::ApiClient;
use hyper::header::{Authorization, Basic, Bearer};
use serde_json;

use config::BitbucketCfg;
use error::{BitbucketError, BitbucketResult};
use types::*;

pub struct BitbucketClient {
    pub config: BitbucketCfg,
}

impl BitbucketClient {
    pub fn new(config: BitbucketCfg) -> Self {
        BitbucketClient { config: config }
    }

    // This function takes the code received from the Oauth dance and exchanges
    // it for an access token
    pub fn authenticate(&self, code: &str) -> BitbucketResult<String> {
        // TODO JB: make the version here dynamic
        let client = ApiClient::new(&self.config.web_url, "habitat", "0.54.0", None)
            .map_err(BitbucketError::ApiClient)?;
        let query = format!("grant_type=authorization_code&code={}", code);
        let mut req = client.post_with_custom_url(
            "site/oauth2/access_token",
            |url| url.set_query(Some(&query)),
        );
        req = req.header(Authorization(Basic {
            username: self.config.client_id.clone(),
            password: Some(self.config.client_secret.clone()),
        }));
        let mut resp = req.send().map_err(BitbucketError::HttpClient)?;
        if resp.status.is_success() {
            let mut body = String::new();
            resp.read_to_string(&mut body)?;
            debug!("Bitbucket response body, {}", body);
            match serde_json::from_str::<AuthOk>(&body) {
                Ok(msg) => Ok(msg.access_token),
                Err(_) => {
                    let err = serde_json::from_str::<AuthErr>(&body)?;
                    Err(BitbucketError::Auth(err))
                }
            }
        } else {
            Err(BitbucketError::HttpResponse(resp.status))
        }
    }

    // This function uses a valid access token to retrieve details about a user. All we really care
    // about is username and email address
    pub fn user(&self, token: &str) -> BitbucketResult<User> {
        // TODO JB: make the version here dynamic
        let client = ApiClient::new(&self.config.api_url, "habitat", "0.54.0", None)
            .map_err(BitbucketError::ApiClient)?;
        let mut req = client.get("1.0/user");
        req = req.header(Authorization(Bearer { token: token.to_string() }));
        let mut resp = req.send().map_err(BitbucketError::HttpClient)?;
        if resp.status.is_success() {
            let mut body = String::new();
            resp.read_to_string(&mut body)?;
            debug!("Bitbucket response body, {}", body);
            match serde_json::from_str::<UserOk>(&body) {
                Ok(msg) => Ok(msg.user),
                Err(e) => {
                    return Err(BitbucketError::ApiError(resp.status, e));
                }
            }
        } else {
            Err(BitbucketError::HttpResponse(resp.status))
        }
    }
}
