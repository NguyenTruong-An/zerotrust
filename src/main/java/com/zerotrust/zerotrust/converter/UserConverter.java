package com.zerotrust.zerotrust.converter;

import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserConverter {
    private final ModelMapper modelMapper;

    public UserResponseDTO convertToDto (UserEntity entity){
        UserResponseDTO result = modelMapper.map(entity, UserResponseDTO.class);
        return result;
    }
}
