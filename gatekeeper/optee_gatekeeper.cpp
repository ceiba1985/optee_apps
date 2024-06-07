/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "OpteeGateKeeper"

#include <endian.h>
#include <limits>

#include <android-base/logging.h>
#include <gatekeeper/password_handle.h>
#include <hardware/hw_auth_token.h>

#include <gatekeeper_ipc.h>
#include "optee_gatekeeper.h"

namespace aidl::android::hardware::gatekeeper {

using ::gatekeeper::ERROR_INVALID;
using ::gatekeeper::ERROR_NONE;
using ::gatekeeper::ERROR_RETRY;
using ::gatekeeper::SizedBuffer;
using ::gatekeeper::VerifyRequest;
using ::gatekeeper::VerifyResponse;

constexpr const uint32_t SEND_BUF_SIZE = 8192;
constexpr const uint32_t RECV_BUF_SIZE = 8192;

OpteeGateKeeperDevice::OpteeGateKeeperDevice()
    : connected_(false)
{
    initialize();
    connect();
}

OpteeGateKeeperDevice::~OpteeGateKeeperDevice() {
    disconnect();
    finalize();
}

bool OpteeGateKeeperDevice::getConnected() {
    ALOGD("%s %d connected_ = %d", __func__, __LINE__, connected_);
    return connected_;
}

SizedBuffer vec2sized_buffer(const std::vector<uint8_t>& vec)
{
    if (vec.size() == 0 || vec.size() > std::numeric_limits<uint32_t>::max())
		return {};

    auto buffer = new uint8_t[vec.size()];
    std::copy(vec.begin(), vec.end(), buffer);
    return {buffer, static_cast<uint32_t>(vec.size())};
}

void sizedBuffer2AidlHWToken(SizedBuffer& buffer,
                             android::hardware::security::keymint::HardwareAuthToken* aidlToken)
{
    const hw_auth_token_t* authToken =
            reinterpret_cast<const hw_auth_token_t*>(buffer.Data<uint8_t>());
    aidlToken->challenge = authToken->challenge;
    aidlToken->userId = authToken->user_id;
    aidlToken->authenticatorId = authToken->authenticator_id;
    // these are in network order: translate to host
    aidlToken->authenticatorType =
            static_cast<android::hardware::security::keymint::HardwareAuthenticatorType>(
                    be32toh(authToken->authenticator_type));
    aidlToken->timestamp.milliSeconds = be64toh(authToken->timestamp);
    aidlToken->mac.insert(aidlToken->mac.begin(), std::begin(authToken->hmac),
                          std::end(authToken->hmac));
}

::ndk::ScopedAStatus OpteeGateKeeperDevice::enroll(
        int32_t uid, const std::vector<uint8_t>& currentPasswordHandle,
        const std::vector<uint8_t>& currentPassword, const std::vector<uint8_t>& desiredPassword,
        GatekeeperEnrollResponse* rsp)
{

	if (!connected_) {
        ALOGE("Device is not connected");
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    if (desiredPassword.size() == 0) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    if (currentPasswordHandle.size() > 0) {
        if (currentPasswordHandle.size() != sizeof(::gatekeeper::password_handle_t)) {
            ALOGE("Password handle has wrong length");
            return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
        }
    }

    /*
     * Enroll request layout
     * +--------------------------------+---------------------------------+
     * | Name                           | Number of bytes                 |
     * +--------------------------------+---------------------------------+
     * | uid                            | 4                               |
     * | desired_password_length        | 4                               |
     * | desired_password               | #desired_password_length        |
     * | current_password_length        | 4                               |
     * | current_password               | #current_password_length        |
     * | current_password_handle_length | 4                               |
     * | current_password_handle        | #current_password_handle_length |
     * +--------------------------------+---------------------------------+
     */
    const uint32_t request_size = sizeof(uid) +
        sizeof(desiredPassword.size()) +
        desiredPassword.size() +
        sizeof(currentPassword.size()) +
        currentPassword.size() +
        sizeof(currentPasswordHandle.size()) +
        currentPasswordHandle.size();
    uint8_t request[request_size];

    uint8_t *i_req = request;
    serialize_int(&i_req, uid);
    serialize_blob(&i_req, desiredPassword.data(), desiredPassword.size());
    serialize_blob(&i_req, currentPassword.data(), currentPassword.size());
    serialize_blob(&i_req, currentPasswordHandle.data(),
            currentPasswordHandle.size());

    uint32_t response_size = RECV_BUF_SIZE;
    uint8_t response[response_size];

    if(!Send(GK_ENROLL, request, request_size, response, response_size)) {
        ALOGE("Enroll failed without respond");
		return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    const uint8_t *i_resp = response;
    uint32_t error;

    /*
     * Enroll response layout
     * +--------------------------------+---------------------------------+
     * | Name                           | Number of bytes                 |
     * +--------------------------------+---------------------------------+
     * | error                          | 4                               |
     * +--------------------------------+---------------------------------+
     * | retry_timeout                  | 4                               |
     * +------------------------------ OR --------------------------------+
     * | response_handle_length         | 4                               |
     * | response_handle                | #response_handle_length         |
     * +--------------------------------+---------------------------------+
     */
    deserialize_int(&i_resp, &error);

    if (error == ERROR_RETRY) {
        uint32_t retry_timeout;
        deserialize_int(&i_resp, &retry_timeout);
        ALOGV("Enroll returns retry timeout %u", retry_timeout);
		*rsp = {ERROR_RETRY_TIMEOUT, static_cast<int32_t>(response.retry_timeout), 0, {}};
		return ndk::ScopedAStatus::ok();
    }

	if (response.error != ERROR_NONE) {
        ALOGE("Enroll failed");
		return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
	}

    const uint8_t *response_handle = nullptr;
    uint32_t response_handle_length = 0;

    deserialize_blob(&i_resp, &response_handle, &response_handle_length);

    std::unique_ptr<uint8_t []> response_handle_ret(
            new (std::nothrow) uint8_t[response_handle_length]);
    if (!response_handle_ret) {
        ALOGE("Cannot create enrolled password handle, not enough memory");
		return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    memcpy(response_handle_ret.get(), response_handle, response_handle_length);

	::gatekeeper::password_handle_t *password_handle =
						(::gatekeeper::password_handle_t *)response_handle_ret.get();
	*rsp = {STATUS_OK,
		0,
		static_cast<int64_t>(password_handle->user_id),
		{(uint8_t *)response_handle_ret.get(),
			((uint8_t *)response_handle_ret.get() + response_handle_length)}};

    ALOGV("Enroll returns success");

	return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus OpteeGateKeeperDevice::verify(
        int32_t uid, int64_t challenge, const std::vector<uint8_t>& enrolledPasswordHandle,
        const std::vector<uint8_t>& providedPassword, GatekeeperVerifyResponse* rsp)
{
	ALOGV("Start verify");

    if (!connected_) {
        ALOGE("Device is not connected");
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    if (enrolledPasswordHandle.size() == 0) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    /*
     * Verify request layout
     * +---------------------------------+----------------------------------+
     * | Name                            | Number of bytes                  |
     * +---------------------------------+----------------------------------+
     * | uid                             | 4                                |
     * | challenge                       | 8                                |
     * | enrolled_password_handle_length | 4                                |
     * | enrolled_password_handle        | #enrolled_password_handle_length |
     * | provided_password_length        | 4                                |
     * | provided_password               | #provided_password_length        |
     * +---------------------------------+----------------------------------+
     */
    const uint32_t request_size = sizeof(uid) +
        sizeof(challenge) +
        sizeof(enrolledPasswordHandle.size()) +
        enrolledPasswordHandle.size() +
        sizeof(providedPassword.size()) +
        providedPassword.size();
    uint8_t request[request_size];

    uint8_t *i_req = request;
    serialize_int(&i_req, uid);
    serialize_int64(&i_req, challenge);
    serialize_blob(&i_req, enrolledPasswordHandle.data(),
            enrolledPasswordHandle.size());
    serialize_blob(&i_req, providedPassword.data(), providedPassword.size());

    uint32_t response_size = RECV_BUF_SIZE;
    uint8_t response[response_size];

    if(!Send(GK_VERIFY, request, request_size, response, response_size)) {
        ALOGE("Verify failed without respond");
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    const uint8_t *i_resp = response;
    uint32_t error;

    /*
     * Verify response layout
     * +--------------------------------+---------------------------------+
     * | Name                           | Number of bytes                 |
     * +--------------------------------+---------------------------------+
     * | error                          | 4                               |
     * +--------------------------------+---------------------------------+
     * | retry_timeout                  | 4                               |
     * +------------------------------ OR --------------------------------+
     * | response_auth_token_length     | 4                               |
     * | response_auth_token            | #response_handle_length         |
     * | response_request_reenroll      | 4                               |
     * +--------------------------------+---------------------------------+
     */
    deserialize_int(&i_resp, &error);
    if (error == ERROR_RETRY) {
        uint32_t retry_timeout;
        deserialize_int(&i_resp, &retry_timeout);
        ALOGV("Verify returns retry timeout %u", retry_timeout);
		*rsp = {ERROR_RETRY_TIMEOUT, static_cast<int32_t>(response.retry_timeout), 0, {}};
		return ndk::ScopedAStatus::ok();
    } else if (error != ERROR_NONE) {
        ALOGE("Verify failed");
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    const uint8_t *response_auth_token = nullptr;
    uint32_t response_auth_token_length = 0;
    uint32_t response_request_reenroll;

    deserialize_blob(&i_resp, &response_auth_token,
        &response_auth_token_length);

    std::unique_ptr<uint8_t []> auth_token_ret(
            new (std::nothrow) uint8_t[response_auth_token_length]);
    if (!auth_token_ret) {
        ALOGE("Cannot create auth token, not enough memory");
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    memcpy(auth_token_ret.get(), response_auth_token, response_auth_token_length);

    deserialize_int(&i_resp, &response_request_reenroll);

	*rsp = {response_request_reenroll ? STATUS_REENROLL : STATUS_OK, 0, {}};

	SizedBuffer token_buf(auth_token_ret.get(), response_auth_token_length);
	// Convert the hw_auth_token_t to HardwareAuthToken in the response.
	sizedBuffer2AidlHWToken(token_buf, &rsp->hardwareAuthToken);

    ALOGV("Verify returns success");
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus OpteeGateKeeperDevice::deleteUser(int32_t uid) {
	return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_NOT_IMPLEMENTED));
}

::ndk::ScopedAStatus OpteeGateKeeperDevice::deleteAllUsers() {
	return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_NOT_IMPLEMENTED));
}

bool OpteeGateKeeperDevice::initialize()
{
    if (!gatekeeperIPC_.initialize()) {
        ALOGE("Fail to connect to TEE");
        return false;
    }

    return true;
}

bool OpteeGateKeeperDevice::connect()
{
    if (connected_) {
        ALOGE("Device is already connected");
        return false;
    }

    if (!gatekeeperIPC_.connect(TA_GATEKEEPER_UUID)) {
        ALOGE("Fail to load Gatekeeper TA");
        return false;
    }
    connected_ = true;

    ALOGV("Connected");

    return true;
}

void OpteeGateKeeperDevice::disconnect()
{
    if (connected_) {
        gatekeeperIPC_.disconnect();
        connected_ = false;
    }

    ALOGV("Disconnected");
}

void OpteeGateKeeperDevice::finalize()
{
    gatekeeperIPC_.finalize();
}

bool OpteeGateKeeperDevice::Send(uint32_t command,
        const uint8_t *request, uint32_t request_size,
        uint8_t *response, uint32_t& response_size)
{
    return gatekeeperIPC_.call(command, request, request_size,
            response, response_size);
}

}  // namespace aidl::android::hardware::gatekeeper
