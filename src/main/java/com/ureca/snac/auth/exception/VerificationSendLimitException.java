package com.ureca.snac.auth.exception;

import com.ureca.snac.common.BaseCode;
import com.ureca.snac.common.exception.BusinessException;

public class VerificationSendLimitException extends BusinessException {
    public VerificationSendLimitException(BaseCode baseCode) {
        super(baseCode);
    }
}
