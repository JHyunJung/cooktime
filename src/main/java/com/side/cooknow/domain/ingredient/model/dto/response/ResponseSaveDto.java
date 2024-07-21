package com.side.cooknow.domain.ingredient.model.dto.response;

import com.side.cooknow.domain.ingredient.model.Ingredient;
import lombok.Data;

@Data
public class ResponseSaveDto {

    private Long id;
    private String category;
    private String name;

    public ResponseSaveDto(Ingredient ingredient){
        this.id = ingredient.getId();
        this.category = ingredient.getCategory().getKorName();
        this.name = ingredient.getKorName();
    }
}