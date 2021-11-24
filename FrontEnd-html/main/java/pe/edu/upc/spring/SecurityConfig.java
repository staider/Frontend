package pe.edu.upc.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import pe.edu.upc.spring.auth.handler.LoginSuccessHandler;
import pe.edu.upc.spring.security.ArrendadorDetailsServiceImpl;
import pe.edu.upc.spring.security.EstudianteDetailsServiceImpl;

@EnableGlobalMethodSecurity(securedEnabled = true)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private EstudianteDetailsServiceImpl eDetailsService;
	
	@Autowired
	private ArrendadorDetailsServiceImpl aDetailsService;
	
	@Autowired
	private LoginSuccessHandler successHandler;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(aDetailsService).passwordEncoder(passwordEncoder());
		
		auth.userDetailsService(eDetailsService).passwordEncoder(passwordEncoder());
	}
	
	/*protected void confg(AuthenticationManagerBuilder auth) throws Exception{
		auth.userDetailsService(eDetailsService).passwordEncoder(passwordEncoder());
	}*/

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		try {
			http.authorizeRequests()
			    .antMatchers("/arrendador/**").access("hasRole('ROLE_ARRENDADOR')")
			    .antMatchers("/habitacion/**").access("hasRole('ROLE_ARRENDADOR')")
			    
			    .antMatchers("/estudiante/**").access("hasRole('ROLE_ARRENDADOR')")
			    .antMatchers("/interes/**").access("hasRole('ROLE_ARRENDADOR')")
			    .and()
				.formLogin().successHandler(successHandler).loginPage("/auth/login").loginProcessingUrl("/auth/login").defaultSuccessUrl("/private/index")
				.permitAll().and().logout().logoutUrl("/logout").logoutSuccessUrl("/public/index").permitAll().and().exceptionHandling().accessDeniedPage("/error");
			
				
		}
		catch(Exception ex) {
			System.out.println(ex.getMessage());
		}
		
		/*http.authorizeRequests().antMatchers("/", "/css/**", "/js/**", "/img/**").permitAll().anyRequest()
		.authenticated()
		.and()
			.formLogin().loginPage("/auth/login").permitAll()
		.and()
			.logout().permitAll()
		.and()
			.exceptionHandling().accessDeniedPage("/error");*/
		
		/*http.authorizeRequests()
		.antMatchers("/","/auth/**","/public/**","/css/**","/js/**").permitAll()
		.antMatchers("/arrendador/**").access("hasRole('ROLE_ARRENDADOR')")
		
		.and()
			.formLogin().loginPage("/auth/login").defaultSuccessUrl("/private/index",true).failureUrl("/auth/login?error=true")
			.loginProcessingUrl("/auth/login-post").permitAll()
		/*.and()
			.formLogin().loginPage("/auth/loginA").defaultSuccessUrl("/private/index2",true).failureUrl("/auth/loginA?error=true")
			.loginProcessingUrl("auth/loginA-post").permitAll()*/
		/*.and()
			.logout().logoutUrl("/logout").logoutSuccessUrl("/public/index");*/	

	}
}
