package jwt.hello.vo;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JwtUser {

    private String username;
    @JsonProperty( value = "password", access = JsonProperty.Access.WRITE_ONLY)
    private String password;
    private String roles;
    
}
