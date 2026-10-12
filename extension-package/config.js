export default {
  "protocol": "pines-tlsn-bridge-v1",
  "wasmVersion": "0.1.0-alpha.15",
  "origins": [
    "https://app.pines.family",
    "https://front.pines.family",
    "https://pines.family",
    "http://localhost:5270",
    "http://localhost:5180",
    "http://127.0.0.1:5180"
  ],
  "verifierOrigin": "https://id.pines.family",
  "verifierRevision": "tee-v5-20261012",
  "verifierPolicy": {
    "host": "*.verifier.pines.family",
    "legacy": [
      "https://id.pines.family"
    ],
    "test": []
  },
  "routing": [
    "pinned"
  ],
  "testBuild": false,
  "application": "pines",
  "chainId": 8453,
  "captureProvider": true,
  "tee": {
    "api": "https://id.pines.family/tee",
    "relay": "wss://id.pines.family/channel",
    "apiKey": "aa2381f0f5817a8e109a6b8eea3061224738c3bf77ea9b0df447023129ca1abd",
    "policySet": {
      "format": "pines-tee-native-policy-set-v1",
      "context": {
        "application": "pines",
        "chain": 8453,
        "revision": "tee-v5-20261012",
        "verificationEpoch": "pines-tee-v5-20261012",
        "protocolVersion": "pines-tee-native-v2",
        "trustPolicyVersion": 3
      },
      "providers": [
        {
          "id": "chatgpt",
          "schema": {
            "schemaId": "pines.chatgpt.tee.native",
            "version": 6,
            "digest": "sha256:cd5e6039d98ecc181ca5f965515cf6eaa5a8dbc621ecd7673c492143f5fe223d"
          },
          "inventorySha256": "5dd28d13b4ccf2547482513fa16733e125e1672834a2065f08fd466fc67886fa",
          "policy": {
            "profile": "pines.chatgpt.tee.native.nitro.v1",
            "admissionEnabled": true,
            "providerQualified": true,
            "clockQualified": true,
            "lifecycleQualified": true,
            "measurements": [
              "1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4"
            ],
            "pcrTuples": [
              [
                "1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4",
                "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
                "1b38ddf5ed6fed44572e5187608a5c32bdb59c536c61adbb2e13450a149fa4a0b0c0af63425621845c98e96fee05f427"
              ]
            ],
            "simulationAllowed": false,
            "debugAllowed": false,
            "providerHost": "chatgpt.com",
            "providerPort": 443,
            "channelVsockPort": 8000,
            "providerEgressVsockPort": 8001,
            "parentCid": 3,
            "limits": {
              "maxSentBytes": 8192,
              "maxRecvBytes": 8192,
              "maxHeaderBytes": 4096,
              "maxBodyBytes": 3584,
              "maxJsonDepth": 8,
              "sessionTimeoutMs": 120000,
              "maxRecvRecords": 64,
              "maxDecodedBodyBytes": 16384,
              "maxChunks": 16,
              "maxRevealedRecvBytes": 4096,
              "maxRevealedSentBytes": 1024,
              "protocolBytesPerDirection": 67108864
            },
            "verificationEpoch": "pines-tee-v5-20261012",
            "trustPolicyVersion": 3,
            "revokedBootIds": [],
            "revokedWorkerIds": [],
            "revokedMeasurements": [],
            "identity": {
              "generation": "v2",
              "protocol": "pines-keyed-receipt-v2",
              "keyArn": "arn:aws:kms:ap-southeast-2:594194277294:key/3d63a788-0acf-42c1-b20c-1c3bdd9e2375",
              "wrappedSha256": "96d0ced12724aae52577a418cf00dbe7cabf85c327ac7bb1cb900dfdd07d9af1",
              "configurationAuthority": "ece4f5e90c2344e7551daa7e933b0b2a32b28b4d108e9c1636b0dce786822cc7",
              "configurationSha256": "be48fb19803397de79e6b7afcd9213dd1e88a9efa77890a0a7124e62f36c6c0c"
            }
          }
        },
        {
          "id": "claude",
          "schema": {
            "schemaId": "pines.claude.tee.native",
            "version": 3,
            "digest": "sha256:b8209443cbf6aa759e9bef8b808de111e0de7837773612facb7387f4726738e2"
          },
          "inventorySha256": "d855bdb5dc2d87a9105f47308516eb4ba64593411c120f139c366aa4908330b1",
          "policy": {
            "profile": "pines.claude.tee.native.nitro.v1",
            "admissionEnabled": true,
            "providerQualified": true,
            "clockQualified": true,
            "lifecycleQualified": true,
            "measurements": [
              "1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4"
            ],
            "pcrTuples": [
              [
                "1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4",
                "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
                "1b38ddf5ed6fed44572e5187608a5c32bdb59c536c61adbb2e13450a149fa4a0b0c0af63425621845c98e96fee05f427"
              ]
            ],
            "simulationAllowed": false,
            "debugAllowed": false,
            "providerHost": "claude.ai",
            "providerPort": 443,
            "channelVsockPort": 8000,
            "providerEgressVsockPort": 8002,
            "parentCid": 3,
            "limits": {
              "maxSentBytes": 8192,
              "maxRecvBytes": 8192,
              "maxHeaderBytes": 4096,
              "maxBodyBytes": 3584,
              "maxJsonDepth": 8,
              "sessionTimeoutMs": 120000,
              "maxRecvRecords": 64,
              "maxDecodedBodyBytes": 12288,
              "maxChunks": 16,
              "maxRevealedRecvBytes": 4096,
              "maxRevealedSentBytes": 1024,
              "protocolBytesPerDirection": 67108864
            },
            "verificationEpoch": "pines-tee-v5-20261012",
            "trustPolicyVersion": 3,
            "revokedBootIds": [],
            "revokedWorkerIds": [],
            "revokedMeasurements": [],
            "identity": {
              "generation": "v2",
              "protocol": "pines-keyed-receipt-v2",
              "keyArn": "arn:aws:kms:ap-southeast-2:594194277294:key/3d63a788-0acf-42c1-b20c-1c3bdd9e2375",
              "wrappedSha256": "96d0ced12724aae52577a418cf00dbe7cabf85c327ac7bb1cb900dfdd07d9af1",
              "configurationAuthority": "ece4f5e90c2344e7551daa7e933b0b2a32b28b4d108e9c1636b0dce786822cc7",
              "configurationSha256": "be48fb19803397de79e6b7afcd9213dd1e88a9efa77890a0a7124e62f36c6c0c"
            }
          }
        },
        {
          "id": "grok",
          "schema": {
            "schemaId": "pines.grok.tee.native",
            "version": 3,
            "digest": "sha256:72127c492d778072c103b374177cc6d71f60e0a49ccac7aa1b23fb6da80aff75"
          },
          "inventorySha256": "9a7978653b2af053b58ff39234d49a2e8317bb8d789e85e71094f4b1f6d5c591",
          "policy": {
            "profile": "pines.grok.tee.native.nitro.v1",
            "admissionEnabled": true,
            "providerQualified": true,
            "clockQualified": true,
            "lifecycleQualified": true,
            "measurements": [
              "1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4"
            ],
            "pcrTuples": [
              [
                "1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4",
                "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
                "1b38ddf5ed6fed44572e5187608a5c32bdb59c536c61adbb2e13450a149fa4a0b0c0af63425621845c98e96fee05f427"
              ]
            ],
            "simulationAllowed": false,
            "debugAllowed": false,
            "providerHost": "grok.com",
            "providerPort": 443,
            "channelVsockPort": 8000,
            "providerEgressVsockPort": 8003,
            "parentCid": 3,
            "limits": {
              "maxSentBytes": 8192,
              "maxRecvBytes": 8192,
              "maxHeaderBytes": 4096,
              "maxBodyBytes": 3584,
              "maxJsonDepth": 8,
              "sessionTimeoutMs": 120000,
              "maxRecvRecords": 64,
              "maxDecodedBodyBytes": 8192,
              "maxChunks": 16,
              "maxRevealedRecvBytes": 4096,
              "maxRevealedSentBytes": 1024,
              "protocolBytesPerDirection": 67108864
            },
            "verificationEpoch": "pines-tee-v5-20261012",
            "trustPolicyVersion": 3,
            "revokedBootIds": [],
            "revokedWorkerIds": [],
            "revokedMeasurements": [],
            "identity": {
              "generation": "v2",
              "protocol": "pines-keyed-receipt-v2",
              "keyArn": "arn:aws:kms:ap-southeast-2:594194277294:key/3d63a788-0acf-42c1-b20c-1c3bdd9e2375",
              "wrappedSha256": "96d0ced12724aae52577a418cf00dbe7cabf85c327ac7bb1cb900dfdd07d9af1",
              "configurationAuthority": "ece4f5e90c2344e7551daa7e933b0b2a32b28b4d108e9c1636b0dce786822cc7",
              "configurationSha256": "be48fb19803397de79e6b7afcd9213dd1e88a9efa77890a0a7124e62f36c6c0c"
            }
          }
        }
      ]
    },
    "providers": [
      {
        "schema": {
          "format": "pines-verification-schema-v1",
          "schemaId": "pines.chatgpt.tee.native",
          "version": 6,
          "providerId": "CHATGPT-SUBSCRIPTION",
          "lifecycle": "qualified",
          "request": {
            "origin": "https://chatgpt.com",
            "method": "GET",
            "path": "/backend-api/wham/usage",
            "query": {},
            "body": {
              "kind": "empty"
            }
          },
          "capture": {
            "navigationUrl": "https://chatgpt.com/#settings/Usage",
            "authOrigins": [
              "https://chatgpt.com"
            ],
            "headers": [
              {
                "name": "authorization",
                "required": true,
                "secret": true,
                "validation": "bearer"
              },
              {
                "name": "user-agent",
                "required": true,
                "secret": false,
                "validation": "visible-ascii"
              }
            ],
            "cookies": []
          },
          "replay": {
            "transform": "fixed-request-v1",
            "headers": {
              "accept": "application/json"
            }
          },
          "limits": {
            "maxSentBytes": 8192,
            "maxRecvBytes": 8192,
            "maxHeaderBytes": 4096,
            "maxBodyBytes": 3584,
            "maxJsonDepth": 8,
            "sessionTimeoutMs": 120000,
            "maxRecvRecords": 64,
            "concurrency": 1,
            "maxDecodedBodyBytes": 16384,
            "maxChunks": 16,
            "maxRevealedRecvBytes": 4096,
            "maxRevealedSentBytes": 1024
          },
          "response": {
            "status": 200,
            "contentType": "application/json",
            "disclosure": "full-json-body",
            "privacy": {
              "mode": "private-headers-v1",
              "visibleHeaders": [
                "content-type",
                "content-length",
                "transfer-encoding",
                "content-encoding"
              ],
              "encodings": [
                "gzip",
                "identity"
              ]
            }
          },
          "fields": [
            {
              "id": "plan_type",
              "pointer": "/plan_type",
              "type": "string"
            },
            {
              "id": "user_id",
              "pointer": "/user_id",
              "type": "string"
            }
          ],
          "checks": [
            {
              "op": "in",
              "field": "plan_type",
              "values": [
                "plus",
                "pro",
                "prolite",
                "promax"
              ]
            },
            {
              "op": "custom",
              "field": "user_id",
              "handler": "chatgpt-user-id-v1"
            }
          ],
          "identity": {
            "version": "chatgpt-private-keyed-v2",
            "kind": "field",
            "field": "user_id"
          },
          "claims": {
            "enabled": true,
            "domain": "chatgpt.com",
            "templateIds": [
              "CHATGPT-SUBSCRIPTION"
            ]
          }
        },
        "reference": {
          "schemaId": "pines.chatgpt.tee.native",
          "version": 6,
          "digest": "sha256:cd5e6039d98ecc181ca5f965515cf6eaa5a8dbc621ecd7673c492143f5fe223d"
        },
        "profile": "pines.chatgpt.tee.native.nitro.v1",
        "publicPlanValues": [
          "plus",
          "pro",
          "prolite",
          "promax"
        ],
        "policy": {
          "profile": "pines.chatgpt.tee.native.nitro.v1",
          "admissionEnabled": true,
          "providerQualified": true,
          "clockQualified": true,
          "lifecycleQualified": true,
          "measurements": [
            "1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4"
          ],
          "pcrTuples": [
            [
              "1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4",
              "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
              "1b38ddf5ed6fed44572e5187608a5c32bdb59c536c61adbb2e13450a149fa4a0b0c0af63425621845c98e96fee05f427"
            ]
          ],
          "simulationAllowed": false,
          "debugAllowed": false,
          "providerHost": "chatgpt.com",
          "providerPort": 443,
          "channelVsockPort": 8000,
          "providerEgressVsockPort": 8001,
          "parentCid": 3,
          "limits": {
            "maxSentBytes": 8192,
            "maxRecvBytes": 8192,
            "maxHeaderBytes": 4096,
            "maxBodyBytes": 3584,
            "maxJsonDepth": 8,
            "sessionTimeoutMs": 120000,
            "maxRecvRecords": 64,
            "maxDecodedBodyBytes": 16384,
            "maxChunks": 16,
            "maxRevealedRecvBytes": 4096,
            "maxRevealedSentBytes": 1024,
            "protocolBytesPerDirection": 67108864
          },
          "verificationEpoch": "pines-tee-v5-20261012",
          "trustPolicyVersion": 3,
          "revokedBootIds": [],
          "revokedWorkerIds": [],
          "revokedMeasurements": [],
          "identity": {
            "generation": "v2",
            "protocol": "pines-keyed-receipt-v2",
            "keyArn": "arn:aws:kms:ap-southeast-2:594194277294:key/3d63a788-0acf-42c1-b20c-1c3bdd9e2375",
            "wrappedSha256": "96d0ced12724aae52577a418cf00dbe7cabf85c327ac7bb1cb900dfdd07d9af1",
            "configurationAuthority": "ece4f5e90c2344e7551daa7e933b0b2a32b28b4d108e9c1636b0dce786822cc7",
            "configurationSha256": "be48fb19803397de79e6b7afcd9213dd1e88a9efa77890a0a7124e62f36c6c0c"
          }
        }
      },
      {
        "schema": {
          "format": "pines-verification-schema-v1",
          "schemaId": "pines.claude.tee.native",
          "version": 3,
          "providerId": "CLAUDE-PLAN",
          "lifecycle": "qualified",
          "request": {
            "origin": "https://claude.ai",
            "method": "GET",
            "path": "/api/organizations/{org_uuid}",
            "query": {},
            "body": {
              "kind": "empty"
            },
            "pathParams": {
              "org_uuid": {
                "kind": "lowercase-uuid-v1",
                "bindsTo": "/uuid"
              }
            }
          },
          "capture": {
            "navigationUrl": "https://claude.ai/new",
            "authOrigins": [
              "https://claude.ai"
            ],
            "headers": [
              {
                "name": "user-agent",
                "required": true,
                "secret": false,
                "validation": "visible-ascii"
              }
            ],
            "cookies": [
              "sessionKey"
            ],
            "trigger": {
              "pathPrefix": "/api/"
            }
          },
          "replay": {
            "transform": "fixed-request-v1",
            "headers": {
              "accept": "application/json"
            }
          },
          "limits": {
            "maxSentBytes": 8192,
            "maxRecvBytes": 8192,
            "maxHeaderBytes": 4096,
            "maxBodyBytes": 3584,
            "maxJsonDepth": 8,
            "sessionTimeoutMs": 120000,
            "maxRecvRecords": 64,
            "concurrency": 1,
            "maxDecodedBodyBytes": 12288,
            "maxChunks": 16,
            "maxRevealedRecvBytes": 4096,
            "maxRevealedSentBytes": 1024
          },
          "response": {
            "status": 200,
            "contentType": "application/json",
            "disclosure": "full-json-body",
            "privacy": {
              "mode": "private-headers-v1",
              "visibleHeaders": [
                "content-type",
                "content-length",
                "transfer-encoding",
                "content-encoding"
              ],
              "encodings": [
                "gzip",
                "identity"
              ]
            }
          },
          "selector": {
            "kind": "claude-paid-personal-org-single-v1"
          },
          "fields": [
            {
              "id": "organization_uuid",
              "pointer": "/uuid",
              "type": "string"
            },
            {
              "id": "rate_limit_tier",
              "pointer": "/rate_limit_tier",
              "type": "string"
            },
            {
              "id": "capabilities",
              "pointer": "/capabilities",
              "type": "array"
            }
          ],
          "checks": [
            {
              "op": "custom",
              "field": "organization_uuid",
              "handler": "claude-org-uuid-v1"
            },
            {
              "op": "custom",
              "field": "rate_limit_tier",
              "handler": "claude-paid-tier-v1"
            },
            {
              "op": "custom",
              "field": "capabilities",
              "handler": "claude-paid-capabilities-v1"
            }
          ],
          "identity": {
            "version": "claude-private-keyed-v2",
            "kind": "field",
            "field": "organization_uuid"
          },
          "claims": {
            "enabled": true,
            "domain": "claude.ai",
            "templateIds": [
              "CLAUDE-PLAN"
            ]
          }
        },
        "reference": {
          "schemaId": "pines.claude.tee.native",
          "version": 3,
          "digest": "sha256:b8209443cbf6aa759e9bef8b808de111e0de7837773612facb7387f4726738e2"
        },
        "profile": "pines.claude.tee.native.nitro.v1",
        "publicPlanValues": [
          "pro",
          "max"
        ],
        "policy": {
          "profile": "pines.claude.tee.native.nitro.v1",
          "admissionEnabled": true,
          "providerQualified": true,
          "clockQualified": true,
          "lifecycleQualified": true,
          "measurements": [
            "1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4"
          ],
          "pcrTuples": [
            [
              "1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4",
              "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
              "1b38ddf5ed6fed44572e5187608a5c32bdb59c536c61adbb2e13450a149fa4a0b0c0af63425621845c98e96fee05f427"
            ]
          ],
          "simulationAllowed": false,
          "debugAllowed": false,
          "providerHost": "claude.ai",
          "providerPort": 443,
          "channelVsockPort": 8000,
          "providerEgressVsockPort": 8002,
          "parentCid": 3,
          "limits": {
            "maxSentBytes": 8192,
            "maxRecvBytes": 8192,
            "maxHeaderBytes": 4096,
            "maxBodyBytes": 3584,
            "maxJsonDepth": 8,
            "sessionTimeoutMs": 120000,
            "maxRecvRecords": 64,
            "maxDecodedBodyBytes": 12288,
            "maxChunks": 16,
            "maxRevealedRecvBytes": 4096,
            "maxRevealedSentBytes": 1024,
            "protocolBytesPerDirection": 67108864
          },
          "verificationEpoch": "pines-tee-v5-20261012",
          "trustPolicyVersion": 3,
          "revokedBootIds": [],
          "revokedWorkerIds": [],
          "revokedMeasurements": [],
          "identity": {
            "generation": "v2",
            "protocol": "pines-keyed-receipt-v2",
            "keyArn": "arn:aws:kms:ap-southeast-2:594194277294:key/3d63a788-0acf-42c1-b20c-1c3bdd9e2375",
            "wrappedSha256": "96d0ced12724aae52577a418cf00dbe7cabf85c327ac7bb1cb900dfdd07d9af1",
            "configurationAuthority": "ece4f5e90c2344e7551daa7e933b0b2a32b28b4d108e9c1636b0dce786822cc7",
            "configurationSha256": "be48fb19803397de79e6b7afcd9213dd1e88a9efa77890a0a7124e62f36c6c0c"
          }
        }
      },
      {
        "schema": {
          "format": "pines-verification-schema-v1",
          "schemaId": "pines.grok.tee.native",
          "version": 3,
          "providerId": "GROK-PLAN",
          "lifecycle": "qualified",
          "request": {
            "origin": "https://grok.com",
            "method": "GET",
            "path": "/rest/subscriptions",
            "query": {
              "status": "SUBSCRIPTION_STATUS_ACTIVE"
            },
            "body": {
              "kind": "empty"
            }
          },
          "capture": {
            "navigationUrl": "https://grok.com/",
            "authOrigins": [
              "https://grok.com"
            ],
            "headers": [
              {
                "name": "user-agent",
                "required": true,
                "secret": false,
                "validation": "visible-ascii"
              }
            ],
            "cookies": [
              "sso"
            ],
            "trigger": {
              "pathPrefix": "/rest/"
            }
          },
          "replay": {
            "transform": "fixed-request-v1",
            "headers": {
              "accept": "application/json"
            }
          },
          "limits": {
            "maxSentBytes": 8192,
            "maxRecvBytes": 8192,
            "maxHeaderBytes": 4096,
            "maxBodyBytes": 3584,
            "maxJsonDepth": 8,
            "sessionTimeoutMs": 120000,
            "maxRecvRecords": 64,
            "concurrency": 1,
            "maxDecodedBodyBytes": 8192,
            "maxChunks": 16,
            "maxRevealedRecvBytes": 4096,
            "maxRevealedSentBytes": 1024
          },
          "response": {
            "status": 200,
            "contentType": "application/json",
            "disclosure": "full-json-body",
            "privacy": {
              "mode": "private-headers-v1",
              "visibleHeaders": [
                "content-type",
                "content-length",
                "transfer-encoding",
                "content-encoding"
              ],
              "encodings": [
                "gzip",
                "identity"
              ]
            }
          },
          "selector": {
            "kind": "grok-paid-subscription-v1",
            "maxItems": 4
          },
          "fields": [
            {
              "id": "xai_user_id",
              "pointer": "/xaiUserId",
              "type": "string"
            },
            {
              "id": "tier",
              "pointer": "/tier",
              "type": "string"
            },
            {
              "id": "status",
              "pointer": "/status",
              "type": "string"
            }
          ],
          "checks": [
            {
              "op": "custom",
              "field": "xai_user_id",
              "handler": "grok-user-uuid-v1"
            },
            {
              "op": "custom",
              "field": "tier",
              "handler": "grok-paid-tier-v1"
            },
            {
              "op": "eq",
              "field": "status",
              "value": "SUBSCRIPTION_STATUS_ACTIVE"
            }
          ],
          "identity": {
            "version": "grok-private-keyed-v2",
            "kind": "field",
            "field": "xai_user_id"
          },
          "claims": {
            "enabled": true,
            "domain": "grok.com",
            "templateIds": [
              "GROK-PAGE"
            ]
          }
        },
        "reference": {
          "schemaId": "pines.grok.tee.native",
          "version": 3,
          "digest": "sha256:72127c492d778072c103b374177cc6d71f60e0a49ccac7aa1b23fb6da80aff75"
        },
        "profile": "pines.grok.tee.native.nitro.v1",
        "publicPlanValues": [
          "SUBSCRIPTION_TIER_X_PREMIUM_PLUS",
          "SUBSCRIPTION_TIER_SUPER_GROK_LITE",
          "SUBSCRIPTION_TIER_GROK_PRO",
          "SUBSCRIPTION_TIER_SUPER_GROK_PLUS",
          "SUBSCRIPTION_TIER_SUPER_GROK_PRO"
        ],
        "policy": {
          "profile": "pines.grok.tee.native.nitro.v1",
          "admissionEnabled": true,
          "providerQualified": true,
          "clockQualified": true,
          "lifecycleQualified": true,
          "measurements": [
            "1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4"
          ],
          "pcrTuples": [
            [
              "1ea73f73c91d558de9885b9b364f37e6354266fe65b0619218ea466a5f26492dec8db4cefde5c44d89578bb909cf1aa4",
              "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
              "1b38ddf5ed6fed44572e5187608a5c32bdb59c536c61adbb2e13450a149fa4a0b0c0af63425621845c98e96fee05f427"
            ]
          ],
          "simulationAllowed": false,
          "debugAllowed": false,
          "providerHost": "grok.com",
          "providerPort": 443,
          "channelVsockPort": 8000,
          "providerEgressVsockPort": 8003,
          "parentCid": 3,
          "limits": {
            "maxSentBytes": 8192,
            "maxRecvBytes": 8192,
            "maxHeaderBytes": 4096,
            "maxBodyBytes": 3584,
            "maxJsonDepth": 8,
            "sessionTimeoutMs": 120000,
            "maxRecvRecords": 64,
            "maxDecodedBodyBytes": 8192,
            "maxChunks": 16,
            "maxRevealedRecvBytes": 4096,
            "maxRevealedSentBytes": 1024,
            "protocolBytesPerDirection": 67108864
          },
          "verificationEpoch": "pines-tee-v5-20261012",
          "trustPolicyVersion": 3,
          "revokedBootIds": [],
          "revokedWorkerIds": [],
          "revokedMeasurements": [],
          "identity": {
            "generation": "v2",
            "protocol": "pines-keyed-receipt-v2",
            "keyArn": "arn:aws:kms:ap-southeast-2:594194277294:key/3d63a788-0acf-42c1-b20c-1c3bdd9e2375",
            "wrappedSha256": "96d0ced12724aae52577a418cf00dbe7cabf85c327ac7bb1cb900dfdd07d9af1",
            "configurationAuthority": "ece4f5e90c2344e7551daa7e933b0b2a32b28b4d108e9c1636b0dce786822cc7",
            "configurationSha256": "be48fb19803397de79e6b7afcd9213dd1e88a9efa77890a0a7124e62f36c6c0c"
          }
        }
      }
    ],
    "disclosurePolicy": "private-headers-gzip-v1",
    "capability": {
      "application": "pines",
      "chain": 8453,
      "revision": "tee-v5-20261012",
      "verificationEpoch": "pines-tee-v5-20261012",
      "protocolVersion": "pines-tee-native-v2",
      "trustPolicyVersion": 3,
      "protocol": "pines-tee-native-v2",
      "capabilityVersion": 2,
      "claimSigningAvailable": false,
      "providers": [
        {
          "id": "chatgpt",
          "profile": "pines.chatgpt.tee.native.nitro.v1",
          "schema": {
            "schemaId": "pines.chatgpt.tee.native",
            "version": 6,
            "digest": "sha256:cd5e6039d98ecc181ca5f965515cf6eaa5a8dbc621ecd7673c492143f5fe223d"
          },
          "savedSchemas": [
            {
              "schemaId": "pines.chatgpt.tee.native",
              "version": 6,
              "digest": "sha256:cd5e6039d98ecc181ca5f965515cf6eaa5a8dbc621ecd7673c492143f5fe223d"
            }
          ]
        },
        {
          "id": "claude",
          "profile": "pines.claude.tee.native.nitro.v1",
          "schema": {
            "schemaId": "pines.claude.tee.native",
            "version": 3,
            "digest": "sha256:b8209443cbf6aa759e9bef8b808de111e0de7837773612facb7387f4726738e2"
          },
          "savedSchemas": [
            {
              "schemaId": "pines.claude.tee.native",
              "version": 3,
              "digest": "sha256:b8209443cbf6aa759e9bef8b808de111e0de7837773612facb7387f4726738e2"
            }
          ]
        },
        {
          "id": "grok",
          "profile": "pines.grok.tee.native.nitro.v1",
          "schema": {
            "schemaId": "pines.grok.tee.native",
            "version": 3,
            "digest": "sha256:72127c492d778072c103b374177cc6d71f60e0a49ccac7aa1b23fb6da80aff75"
          },
          "savedSchemas": [
            {
              "schemaId": "pines.grok.tee.native",
              "version": 3,
              "digest": "sha256:72127c492d778072c103b374177cc6d71f60e0a49ccac7aa1b23fb6da80aff75"
            }
          ]
        }
      ]
    }
  },
  "schemas": [
    {
      "schemaId": "pines.chatgpt.tee.native",
      "version": 6,
      "digest": "sha256:cd5e6039d98ecc181ca5f965515cf6eaa5a8dbc621ecd7673c492143f5fe223d"
    },
    {
      "schemaId": "pines.claude.tee.native",
      "version": 3,
      "digest": "sha256:b8209443cbf6aa759e9bef8b808de111e0de7837773612facb7387f4726738e2"
    },
    {
      "schemaId": "pines.grok.tee.native",
      "version": 3,
      "digest": "sha256:72127c492d778072c103b374177cc6d71f60e0a49ccac7aa1b23fb6da80aff75"
    }
  ],
  "chatgptClaims": false,
  "chatgptIdentity": true,
  "extensionId": "lanmbpkmblcijblbllbikenpnceidmpj"
};
