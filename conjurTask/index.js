"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const tl = require("azure-pipelines-task-lib/task");
const https = require("https");
const fs_1 = __importDefault(require("fs"));
const readline = require('readline');
// utility functions
function trimRight(input, trimStr) {
    var _a;
    if ((_a = input) === null || _a === void 0 ? void 0 : _a.endsWith(trimStr)) {
        input = input.substring(0, input.length - 1);
        return trimRight(input, trimStr);
    }
    return input;
}
function removeHttps(input) {
    return input.replace("https://", "").replace("http://", "");
}
function base64(input) {
    return Buffer.from(input).toString('base64');
}
function getTokenHeader(token) {
    return "Token token=\"" + base64(token) + "\"";
}
function sendHttpRequest(hostname, endpoint, method, authorization, data, ignoreSsl) {
    // very helpful for debugging but does leak passwords/tokens when in debug mode
    // console.debug(`------------\n${method} ${hostname}${endpoint}\nAuthorization: ${authorization}\n\n${data}`)
    if (ignoreSsl) {
        // this will auto prompt with warning
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    }
    // posting data must include Content-Length in HTTP header
    var dataLength = 0;
    if (data) {
        dataLength = data.length;
    }
    return new Promise((resolve, reject) => {
        const options = {
            hostname: hostname,
            port: 443,
            path: endpoint,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': dataLength,
                'Authorization': authorization
            }
        };
        var responseBody = [];
        const req = https.request(options, (res) => {
            res.on('data', (chunk) => responseBody.push(chunk));
            res.on('end', () => resolve(responseBody.join('')));
            // If non-200 code is returned from any call using this method the task extension will fail
            if (res.statusCode != 200) {
                tl.setResult(tl.TaskResult.Failed, `recieved status code '${res.statusCode}': ${responseBody.join('')}`);
            }
        });
        req.on('error', (error) => {
            console.error(error);
        });
        if (data) {
            req.write(data);
        }
        req.end();
    });
}
// conjur api functions
function authenticate(hostname, account, username, apiKey, type, ignoreSsl) {
    switch (type) {
        case AuthnTypes.ApiKey:
            username = encodeURIComponent(username);
            var endpoint = `/authn/${account}/${username}/authenticate`;
            return sendHttpRequest(hostname, endpoint, 'POST', "", apiKey, ignoreSsl);
        default:
            tl.setResult(tl.TaskResult.Failed, `Invalid authentication type '${type}'. Valid types are 'apiKey'`);
    }
}
function getSecret(hostname, account, token, secretId, ignoreSsl) {
    var endpoint = `/secrets/${account}/variable/${secretId}`;
    token = getTokenHeader(token);
    return sendHttpRequest(hostname, endpoint, 'GET', token, null, ignoreSsl);
}
function createISecret(line) {
    var secretSections = line.split(": !var ");
    if (secretSections.length != 2) {
        tl.setResult(tl.TaskResult.Failed, `Failed to retrieve secret name and path from '${line}'`);
    }
    var secretName = secretSections[0].trim();
    var secretPath = secretSections[1].trim();
    var secret = {
        name: secretName,
        path: secretPath
    };
    return secret;
}
function setAzureSecret(secret, secretValue) {
    tl.setVariable(secret.name, secretValue, true);
    console.log(`Set conjur secret '${secret.path}' to azure variable '${secret.name}'`);
}
function getSecrets(hostname, account, token, secretYml, ignoreSsl) {
    // read the secrets yml
    const readInterface = readline.createInterface({
        input: fs_1.default.createReadStream(secretYml),
        output: process.stdout,
        console: false
    });
    readInterface.on('line', function (line) {
        if (line.toString().includes(': !var')) {
            // get secret for each line in secrets.yml that contains ': !var'
            var secret = createISecret(line);
            getSecret(hostname, account, token, secret.path, ignoreSsl)
                .then((data) => setAzureSecret(secret, data.toString()))
                .catch((err) => tl.setResult(tl.TaskResult.Failed, err.message));
        }
    });
}
var AuthnTypes;
(function (AuthnTypes) {
    AuthnTypes[AuthnTypes["ApiKey"] = 0] = "ApiKey";
    AuthnTypes[AuthnTypes["AzureManagedIdentity"] = 1] = "AzureManagedIdentity";
})(AuthnTypes || (AuthnTypes = {}));
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            // fetch from input
            var hostname = tl.getInput('conjurapplianceurl', true);
            var account = tl.getInput('conjuraccount', true);
            var username = tl.getInput('conjurusername', true);
            var apiKey = tl.getInput('conjurapikey', true);
            var secretYml = tl.getInput('secretsyml', false);
            var authnTypeInput = tl.getInput('authntype', false);
            var ignoreSsl = tl.getBoolInput('ignoressl', false);
            // Set defaults
            if (!hostname) {
                hostname = "";
            }
            if (!account) {
                account = "";
            }
            if (!username) {
                username = "";
            }
            if (!apiKey) {
                apiKey = '';
            }
            if (!secretYml) {
                secretYml = './secrets.yml';
            }
            // define authentication types
            var authnType = AuthnTypes.ApiKey;
            if (!authnTypeInput) {
                if (authnTypeInput == "azure-managed-identity") {
                    authnType = AuthnTypes.AzureManagedIdentity;
                }
            }
            // sanitize
            hostname = trimRight(hostname, '/');
            hostname = removeHttps(hostname);
            // fetch the secrets
            authenticate(hostname, account, username, apiKey, authnType, true)
                .then((data) => getSecrets(hostname, account, data.toString(), secretYml, ignoreSsl))
                .catch((err) => tl.setResult(tl.TaskResult.Failed, err.message))
                .catch((err) => tl.setResult(tl.TaskResult.Failed, err.message));
        }
        catch (err) {
            tl.setResult(tl.TaskResult.Failed, err.message);
        }
    });
}
run();
