package com.myjwtapp.service;

import com.myjwtapp.model.entity.User;
import com.myjwtapp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class UserLoginAttemptService {

    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final long LOCK_TIME_DURATION = 3 * 60 * 60 * 1000;
    private static final int RESET_ATTEMPTS = 0;

    private final UserRepository userRepository;

    public boolean isAccountLocked(User user) {
        if (user.isAccountNonLocked()) {
            return false;
        }
        return !unlockWhenTimeExpired(user);
    }

    public void increaseFailedAttempts(User user) {
        int newFailAttempts = user.getFailedAttempt() + 1;
        user.setFailedAttempt(newFailAttempts);
        if (newFailAttempts >= MAX_FAILED_ATTEMPTS) {
            lock(user);
        } else {
            userRepository.save(user);
        }
    }

    public void resetFailedAttempts(User user) {
        user.setFailedAttempt(RESET_ATTEMPTS);
        userRepository.save(user);
    }

    public void lock(User user) {
        user.setAccountLocked(true);
        user.setLockTime(new Date());
        userRepository.save(user);
    }

    public boolean unlockWhenTimeExpired(User user) {
        long lockTimeInMillis = user.getLockTime().getTime();
        long currentTimeInMillis = System.currentTimeMillis();

        if (lockTimeInMillis + LOCK_TIME_DURATION < currentTimeInMillis) {
            user.setAccountLocked(false);
            user.setLockTime(null);
            user.setFailedAttempt(RESET_ATTEMPTS);
            userRepository.save(user);
            return true;
        }
        return false;
    }
}
