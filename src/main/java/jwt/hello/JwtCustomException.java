package jwt.hello;

public class JwtCustomException extends RuntimeException {

	private static final long serialVersionUID = 8408860395013991983L;

	private final JwtErrorCodes errorCode;

	private final Object[] arguments;

	public JwtCustomException(final JwtErrorCodes errorCode, final Object... arguments) {
		super();
		this.errorCode = errorCode;
		this.arguments = arguments;
	}

	public JwtErrorCodes getErrorCode() {
		return errorCode;
	}

	public Object[] getArguments() {
		return arguments;
	}

}
