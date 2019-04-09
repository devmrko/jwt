package jwt.hello.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
     * <B>Project Name : </B>jwt<br/>
     * <B>Package Name : </B>jwt.hello.config<br/>
     * <B>File Name : </B>WebMvcConfigurerImpl<br/>
     * <B>Description</B>
     * <ul>
     * <li>CORS 처리를 위해 필요, CORS 대상 설정
     * </ul>
     *
     * @author Joungmin
     * @since 2019. 4. 9.
     */
@Configuration
public class WebMvcConfigurerImpl implements WebMvcConfigurer {

	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**");
	}

}