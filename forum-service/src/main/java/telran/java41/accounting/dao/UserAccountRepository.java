package telran.java41.accounting.dao;

import org.springframework.data.mongodb.repository.MongoRepository;

import telran.java41.accounting.model.UserAccount;

public interface UserAccountRepository extends MongoRepository<UserAccount, String> {

}
