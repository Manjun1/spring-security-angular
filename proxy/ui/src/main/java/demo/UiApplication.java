package demo;

import java.io.IOException;
import java.security.Principal;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

@Configuration
@ComponentScan
@EnableAutoConfiguration
@RestController
@EnableZuulProxy
@EnableRedisHttpSession
public class UiApplication {

	@RequestMapping("/user")
	public Principal user(Principal user) {
		return user;
	}

	public static void main(String[] args) {
		SpringApplication.run(UiApplication.class, args);
	}

	@Configuration
	@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
	protected static class SecurityConfiguration extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
			.and()
				.logout()       
			.and()
				.authorizeRequests()
					.antMatchers("/index.html", "/home.html", "/login.html", "/").permitAll()
					.anyRequest().authenticated()
			.and()
				.csrf().csrfTokenRepository(csrfTokenRepository())
			.and()
				.addFilterAfter(csrfHeaderFilter(), CsrfFilter.class);
			// @formatter:on
		}
		
		
		
		
		public DriverManagerDataSource dataSource() {
		    DriverManagerDataSource driverManagerDataSource = new DriverManagerDataSource();
		    driverManagerDataSource.setDriverClassName("com.mysql.jdbc.Driver");
		    driverManagerDataSource.setUrl("jdbc:mysql://192.168.59.103:3306/test");
		    driverManagerDataSource.setUsername("root");
		    driverManagerDataSource.setPassword("my-secret-pw");
		    return driverManagerDataSource;
		}
		 @Autowired
		    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			 
		        DataSource ds = dataSource();
		 
		        
		        
		        final String findUserQuery = "select username,password,enabled "
		                + "from Employees " + "where username = ?";
		        final String findRoles = "select username,role " + "from Roles "
		                + "where username = ?";
		         
		        auth.jdbcAuthentication().dataSource(ds)
		                .usersByUsernameQuery(findUserQuery)
		                .authoritiesByUsernameQuery(findRoles);
		        
		    }
		 
		private Filter csrfHeaderFilter() {
			return new OncePerRequestFilter() {
				@Override
				protected void doFilterInternal(HttpServletRequest request,
						HttpServletResponse response, FilterChain filterChain)
						throws ServletException, IOException {
					CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class
							.getName());
					if (csrf != null) {
						Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
						String token = csrf.getToken();
						if (cookie == null || token != null
								&& !token.equals(cookie.getValue())) {
							cookie = new Cookie("XSRF-TOKEN", token);
							cookie.setPath("/");
							response.addCookie(cookie);
						}
					}
					filterChain.doFilter(request, response);
				}
			};
		}

		private CsrfTokenRepository csrfTokenRepository() {
			HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
			repository.setHeaderName("X-XSRF-TOKEN");
			return repository;
		}
	}

}
