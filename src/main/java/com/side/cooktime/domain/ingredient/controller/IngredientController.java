package com.side.cooktime.domain.ingredient.controller;



import com.side.cooktime.domain.ingredient.model.Ingredient;
import com.side.cooktime.domain.ingredient.model.dto.request.RequestSaveDto;
import com.side.cooktime.domain.ingredient.model.dto.response.ResponseDeleteDto;
import com.side.cooktime.domain.ingredient.model.dto.response.ResponseSaveDto;
import com.side.cooktime.domain.ingredient.service.IngredientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1")
public class IngredientController {

    private final IngredientService ingredientService;

    @PostMapping(value = "/ingredient", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ResponseSaveDto> save(RequestSaveDto requestDto) throws IOException {
        Ingredient ingredient = ingredientService.save(requestDto);
        ResponseSaveDto responseDto = new ResponseSaveDto(ingredient);
        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @DeleteMapping("/ingredient/{id}")
    public ResponseEntity<ResponseDeleteDto> delete(@PathVariable("id") Long ingredientId){
        ingredientService.delete(ingredientId);
        return new ResponseEntity<>(new ResponseDeleteDto(ingredientId), HttpStatus.OK);
    }

}
