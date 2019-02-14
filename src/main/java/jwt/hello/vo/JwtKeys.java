package jwt.hello.vo;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JwtKeys {

    private String accessToken;
    private String refreshToken;
    
}
