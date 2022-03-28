package telran.java41.security.filter;

import java.io.IOException;
import java.security.Principal;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import telran.java41.accounting.dao.UserAccountRepository;
import telran.java41.accounting.model.UserAccount;

@Service
@Order(10)
public class AuthenticationFilter implements Filter {

	UserAccountRepository repository;

	@Autowired
	public AuthenticationFilter(UserAccountRepository repository) {
		this.repository = repository;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
	
//		System.out.println(request.getMethod()); // it is checking method
//		System.out.println(request.getServletPath()); // it is checking end point
		
//		Here you can check all the login and password
//		System.out.println(credentials[1]);
//		System.out.println(userAccount.getPassword());

		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			String token = request.getHeader("Authorization");
			//		System.out.println(token);
			String[] credentials;
			try {
				credentials = getCredentialsFromToken(token);
			} catch (Exception e) {
				response.sendError(401, "Token not valid");
				return;
			}
			UserAccount userAccount = repository.findById(credentials[0]).orElse(null);
			if (userAccount == null || !BCrypt.checkpw(credentials[1], userAccount.getPassword())) {
				response.sendError(401, "User don't exist or login or password are not correct"); // cod 401 is an																						// authentication error
				return;
			}
			request = new WrappedRequest(request, userAccount.getLogin());
		}
//		System.out.println(request.getUserPrincipal());
		chain.doFilter(request, response);

	}

	private boolean checkEndPoint(String method, String path) {
		return !("POST".equalsIgnoreCase(method) && path.matches("/account/register/?")); // in matches we have regular expression
	}

	private String[] getCredentialsFromToken(String token) {
		token = token.split(" ")[1]; // take a second element from array with token
		String decode = new String(Base64.getDecoder().decode(token)); // here login and password together as a String
		String[] credentials = decode.split(":"); // here we have change String to array with two elements: login and
													// password separately
		return credentials; // here we take all element of array
	}
	
	private class WrappedRequest extends HttpServletRequestWrapper{
		String login;

		public WrappedRequest(HttpServletRequest request, String login) {
			super(request);
			this.login = login;
		}
		
		@Override
		public Principal getUserPrincipal() {
			return () -> login;
		}
	}

}
