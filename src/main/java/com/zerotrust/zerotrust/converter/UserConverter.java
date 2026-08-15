package com.zerotrust.zerotrust.converter;

import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.model.request.RegisterRequestDTO;
import com.zerotrust.zerotrust.model.response.UserResponseDTO;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserConverter {
    private final ModelMapper modelMapper;

    public UserEntity convertToEntity (RegisterRequestDTO dto){
        UserEntity result = modelMapper.map(dto, UserEntity.class);
        return result;
    }

    public UserResponseDTO convertToDto (UserEntity entity){
        UserResponseDTO result = modelMapper.map(entity, UserResponseDTO.class);
        return result;
    }
}
