package it.spid.cie.oidc.spring.boot.relying.party.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class MvcConfig implements WebMvcConfigurer {

	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/oidc/rp/login").setViewName("login");
		registry.addViewController("/").setViewName("login");
		
	}

}
