package com.zerotrust.zerotrust.service;

import com.zerotrust.zerotrust.model.request.RegisterRequestDTO;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;

import java.util.List;

public interface UserService {
    UserResponseDTO register(RegisterRequestDTO registerRequestDTO);
    List<UserResponseDTO> getAllUsers();
}
