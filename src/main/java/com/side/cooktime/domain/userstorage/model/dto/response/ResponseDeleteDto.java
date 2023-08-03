package com.side.cooktime.domain.userstorage.model.dto.response;

import com.side.cooktime.domain.userstorage.model.UserStorage;
import lombok.Data;

@Data
public class ResponseDeleteDto {

    private Long id;
    private String ingredient_name;

    public ResponseDeleteDto(UserStorage userStorage){
        this.id = userStorage.getId();
        this.ingredient_name = userStorage.getIngredient().getName().getName();
    }
}
