package jwt.hello.vo;

public enum JwtErrorCodes {
	CSC_JWT_EXPIRED("CSC_JWT_EXPIRED"),
	CSC_BAD_CREDENTIALS("CSC_BAD_CREDENTIALS"),
	CSC_URL_FORBIDDEN("CSC_URL_FORBIDDEN"),
	CSC_UNAUTHORIZED("CSC_UNAUTHORIZED"),
	CSC_BAD_TOKEN("CSC_BAD_TOKEN"),
	CSC_CANNOT_REFRESH("CSC_CANNOT_REFRESH");
	
	private final String text;
	
	JwtErrorCodes(final String text) {
        this.text = text;
    }
	
	@Override
    public String toString() {
        return text;
    }
	
}