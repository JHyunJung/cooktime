package com.side.cooktime.domain.userstorage.controller;

import com.side.cooktime.domain.userstorage.model.UserStorage;
import com.side.cooktime.domain.userstorage.model.UserStorages;
import com.side.cooktime.domain.userstorage.model.dto.request.RequestDeleteDto;
import com.side.cooktime.domain.userstorage.model.dto.request.RequestSaveDto;
import com.side.cooktime.domain.userstorage.model.dto.request.RequestUpdateDto;
import com.side.cooktime.domain.userstorage.model.dto.response.*;
import com.side.cooktime.domain.userstorage.service.UserStorageService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1")
@Log4j2
public class UserStorageController {

    private final UserStorageService userStorageService;

    @PostMapping("/storage")
    public ResponseEntity<ResponseSaveDto> save(@RequestBody RequestSaveDto requestDto) {
        List<UserStorage> userStorages = userStorageService.save(requestDto);
        return new ResponseEntity<>(new ResponseSaveDto(userStorages.size()), HttpStatus.CREATED);
    }

    @PutMapping("/storage")
    public ResponseEntity<ResponseUpdateDto> update(@RequestBody RequestUpdateDto requestDto) {
        UserStorages userStorages = userStorageService.update(requestDto);
        return new ResponseEntity<>(new ResponseUpdateDto(userStorages.getSize()), HttpStatus.OK);
    }

    @GetMapping("/storages")
    public ResponseEntity<List<ResponseFindStorageDto>> findStorages(@RequestParam("type") String type){
        UserStorages userStorages = userStorageService.findStorages(type);
        return new ResponseEntity<>(userStorages.toDtos(ResponseFindStorageDto::new), HttpStatus.OK);
    }

    @DeleteMapping("/storage/delete")
    public ResponseEntity<ResponseDeleteDto> delete(@RequestBody RequestDeleteDto requestDto) {
        ResponseDeleteDto responseDto = userStorageService.delete(requestDto);
        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @GetMapping("/storage")
    public ResponseEntity<List<ResponseGetDto>> get() {
        UserStorages userStorages = userStorageService.get();
        return new ResponseEntity<>(userStorages.toDtos(ResponseGetDto::new), HttpStatus.OK);
    }

    @GetMapping("/storage/near-expiry")
    public ResponseEntity<List<ResponseGetNearExpiryDto>> getNearExpiry(){
     List<ResponseGetNearExpiryDto> responseDtoList = userStorageService.getNearExpiry();
     return new ResponseEntity<>(responseDtoList, HttpStatus.OK);
    }
}
