package telran.java41.accounting.service;

import telran.java41.accounting.dto.RolesResponseDto;
import telran.java41.accounting.dto.UserAccountResponseDto;
import telran.java41.accounting.dto.UserRegisterDto;
import telran.java41.accounting.dto.UserUpdateDto;

public interface UserAccountService {
	UserAccountResponseDto addUser(UserRegisterDto userRegisterDto);
	
	UserAccountResponseDto getUser(String login);
	
	UserAccountResponseDto removeUser(String login);
	
	UserAccountResponseDto editUser(String login, UserUpdateDto updateDto);
	
	RolesResponseDto changeRolesList(String login, String role, boolean isAddRole);
	
	void changePassword(String login, String newPassword);
}
