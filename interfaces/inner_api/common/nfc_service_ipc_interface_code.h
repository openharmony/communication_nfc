/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef NFC_SERVICE_IPC_INTERFACE_CODE_H
#define NFC_SERVICE_IPC_INTERFACE_CODE_H

/* said: 1140 */
namespace OHOS {
namespace NFC {
class NfcServiceIpcInterfaceCode {
public:
    enum NfcControllerCode {
        COMMAND_ID = 100,
        COMMAND_GET_STATE,
        COMMAND_TURN_ON,
        COMMAND_TURN_OFF,
        COMMAND_ON_NOTIFY,
        COMMAND_REGISTER_CALLBACK,
        COMMAND_UNREGISTER_CALLBACK,
        COMMAND_IS_NFC_OPEN,
        COMMAND_GET_TAG_INTERFACE,
        COMMAND_REG_FOREGROUND,
        COMMAND_UNREG_FOREGROUND,
        COMMAND_TAG_FOUND_FOREGROUND
    };

    enum TagSessionCode {
        TAG_SESSION_START_ID = 200,
        COMMAND_CONNECT,
        COMMAND_RECONNECT,
        COMMAND_DISCONNECT,
        COMMAND_GET_TECHLIST,
        COMMAND_IS_PRESENT,
        COMMAND_IS_NDEF,
        COMMAND_SEND_RAW_FRAME,
        COMMAND_NDEF_READ,
        COMMAND_NDEF_WRITE,
        COMMAND_NDEF_MAKE_READ_ONLY,
        COMMAND_FORMAT_NDEF,
        COMMAND_CAN_MAKE_READ_ONLY,
        COMMAND_GET_MAX_TRANSCEIVE_LENGTH,
        COMMAND_IS_SUPPORTED_APDUS_EXTENDED,
        COMMAND_SET_TIMEOUT,
        COMMAND_GET_TIMEOUT
    };
}; // NfcServiceIpcInterfaceCode
} // NFC
} // OHOS
#endif // NFC_SERVICE_IPC_INTERFACE_CODE_H