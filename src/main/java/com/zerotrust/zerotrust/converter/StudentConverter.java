package com.zerotrust.zerotrust.converter;

import com.zerotrust.zerotrust.entity.StudentClassEntity;
import com.zerotrust.zerotrust.entity.StudentEntity;
import com.zerotrust.zerotrust.entity.UserEntity;
import com.zerotrust.zerotrust.model.response.StudentResponseDTO;
import org.springframework.stereotype.Component;

@Component
public class StudentConverter {
    public StudentResponseDTO convertToDto(StudentEntity student) {
        UserEntity user = student.getUserEntity();
        StudentClassEntity studentClass = student.getStudentClassEntity();

        return new StudentResponseDTO(
                student.getId(),
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.getStatus(),
                student.getStudentCode(),
                student.getDateOfBirth(),
                student.getGender(),
                student.getPhone(),
                student.getAddress(),
                studentClass.getClassCode(),
                studentClass.getClassName());
    }
}
