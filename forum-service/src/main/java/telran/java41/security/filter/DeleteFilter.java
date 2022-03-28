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
public class DeleteFilter implements Filter {

	UserAccountRepository repository;

	@Autowired
	public DeleteFilter(UserAccountRepository repository) {
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
			if (userAccount.getLogin() != userAccountByCredentials.getLogin() &&
					userAccount.getPassword() != userAccountByCredentials.getPassword()
					|| !userAccount.getRoles().contains("Administrator".toUpperCase())) {
				response.sendError(403);
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private String[] getCredentialsFromToken(String token) {
		token = token.split(" ")[1];
		String decode = new String(Base64.getDecoder().decode(token));
		String[] credentials = decode.split(":");
		return credentials;
	}

	private boolean checkEndPoint(String method, String path) {
		return "DEL".equalsIgnoreCase(method) && path.matches("/account/user/\\w+/?"); // regex
	}

}
