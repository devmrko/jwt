package jwt.hello;

public class JwtCustomException extends RuntimeException {

	private static final long serialVersionUID = 8408860395013991983L;

	private final JwtErrorCodes errorCode;

	private final String errorMessage;

	public JwtCustomException(final JwtErrorCodes errorCode, final String errorMessage, Throwable err) {
		super(errorMessage, err);
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
	}

	public JwtCustomException(final JwtErrorCodes errorCode, final String errorMessage) {
		super(errorMessage);
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
	}

	public JwtErrorCodes getErrorCode() {
		return errorCode;
	}

	public String getCustomMessage() {
		return errorMessage;
	}

}
