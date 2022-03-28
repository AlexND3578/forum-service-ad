package telran.java41.security.filter;

import java.io.IOException;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import telran.java41.accounting.dao.UserAccountRepository;
import telran.java41.accounting.model.UserAccount;

@Service
@Order(20)
public class LoginFilter implements Filter {

	UserAccountRepository repository;

	@Autowired
	public LoginFilter(UserAccountRepository repository) {
		this.repository = repository;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			String token = request.getHeader("Authorization");			
			String[] credentials;
			try {
				credentials = getCredentialsFromToken(token);
			} catch (Exception e) {
				response.sendError(401, "Token not valid");
				return;
			}
			UserAccount userAccountByCredentials = repository.findById(credentials[0]).orElse(null);						
			UserAccount userAccount = repository.findById(request.getUserPrincipal().getName()).get();
			if (userAccount.getLogin() != userAccountByCredentials.getLogin()) {
				response.sendError(403); 
				return;
			}
		}
		chain.doFilter(request, response);
	}
	
	private String[] getCredentialsFromToken(String token) {
		token = token.split(" ")[1]; // take a second element from array with token
		String decode = new String(Base64.getDecoder().decode(token)); // here login and password together as a String
		String[] credentials = decode.split(":"); // here we have change String to array with two elements: login and password separately												
		return credentials; // here we take all element of array
	}
	

	private boolean checkEndPoint(String method, String path) {
		return "POST".equalsIgnoreCase(method) && path.matches("/account/login"); // regex
	}

}
