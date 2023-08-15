package com.side.cooktime.domain.userstorage.controller;

import com.side.cooktime.document.RestDocsTestSupport;
import com.side.cooktime.domain.category.model.Category;
import com.side.cooktime.domain.ingredient.model.Ingredient;
import com.side.cooktime.domain.member.model.Member;
import com.side.cooktime.domain.member.model.User;
import com.side.cooktime.domain.userstorage.model.UserStorage;
import com.side.cooktime.domain.userstorage.model.UserStorages;
import com.side.cooktime.domain.userstorage.model.dto.request.RequestSaveOneDto;
import com.side.cooktime.domain.userstorage.model.dto.response.ResponseDeleteDto;
import com.side.cooktime.domain.userstorage.model.dto.response.ResponseGetDto;
import com.side.cooktime.domain.userstorage.model.dto.response.ResponseSaveDto;
import com.side.cooktime.domain.userstorage.model.dto.response.ResponseUpdateDto;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.*;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


public class UserStorageControllerTest extends RestDocsTestSupport {

    //TODO: Authentication이 null이라서 현재 테스트 불가

    private final List<UserStorage> userStorages = new ArrayList<>();
    private UserStorages userStorageList;

    @BeforeEach
    void setUp() {
        Member member = new User("google", "test", "test@gmail.com", "test123456", "길동", "홍", "MALE", 29);
        Long categoryId = 1L;
        Category category = new Category(categoryId, "고기");
        Ingredient ingredient1 = new Ingredient(1L, "안심", "testUrl", category);
        Ingredient ingredient2 = new Ingredient(2L, "등심", "testUrl", category);

        RequestSaveOneDto requestSaveOneDto = new RequestSaveOneDto();
        requestSaveOneDto.setIngredient_id(1L);
        requestSaveOneDto.setQuantity(15);
        requestSaveOneDto.setExpiration_date(LocalDate.parse("2023-08-10", DateTimeFormatter.ISO_DATE));
        requestSaveOneDto.setStorage_type("COLD");
        UserStorage userStorage1 = requestSaveOneDto.toEntity(member, ingredient1);

        RequestSaveOneDto requestSaveOneDto2 = new RequestSaveOneDto();
        requestSaveOneDto2.setIngredient_id(2L);
        requestSaveOneDto2.setQuantity(30);
        requestSaveOneDto2.setExpiration_date(LocalDate.parse("2023-08-12", DateTimeFormatter.ISO_DATE));
        requestSaveOneDto2.setStorage_type("ROOM");
        UserStorage userStorage2 = requestSaveOneDto2.toEntity(member, ingredient2);

        RequestSaveOneDto requestSaveOneDto3 = new RequestSaveOneDto();
        requestSaveOneDto3.setIngredient_id(2L);
        requestSaveOneDto3.setQuantity(70);
        requestSaveOneDto3.setExpiration_date(LocalDate.parse("2023-09-30", DateTimeFormatter.ISO_DATE));
        requestSaveOneDto3.setStorage_type("FREEZE");
        UserStorage userStorage3 = requestSaveOneDto3.toEntity(member, ingredient2);

        userStorages.add(userStorage1);
        userStorages.add(userStorage2);
        userStorages.add(userStorage3);

        userStorageList = new UserStorages(userStorages);
    }

    @AfterEach
    void afterEach() {
        userStorages.clear();
    }

    @Test
    @DisplayName("Save 201")
    public void save_201() throws Exception {
        ResponseSaveDto responseSaveDto = new ResponseSaveDto(3);

        when(userStorageService.save(any())).thenReturn(userStorages);

        this.mockMvc.perform(post("/api/v1/storage")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"request\": [{\"ingredient_id\": 1,\"quantity\": 15,\"expiration_date\": \"2023-08-10\", \"storage_type\": \"COLD\"},{\"ingredient_id\": 2,\"quantity\": 30,\"expiration_date\": \"2023-08-12\",\"storage_type\": \"ROOM\"},{\"ingredient_id\": 2,\"quantity\": 70,\"expiration_date\": \"2023-09-30\",\"storage_type\": \"FREEZE\"}]}"))
                .andExpect(status().isCreated())
                .andDo(
                        restDocs.document(
                                requestFields(
                                        fieldWithPath("request[].ingredient_id").description("저장할 재료 id"),
                                        fieldWithPath("request[].quantity").description("저장할 재료 양"),
                                        fieldWithPath("request[].expiration_date").description("유통 기한"),
                                        fieldWithPath("request[].storage_type").description("보관 방식")
                                ),
                                responseFields(
                                        fieldWithPath("size").description("저장 된 갯수")
                                )
                        )
                );
    }

    @Test
    @DisplayName("Delete 200")
    public void delete_200() throws Exception {
        ResponseDeleteDto responseDeleteDto = new ResponseDeleteDto("test@gmail.com", userStorages);

        when(userStorageService.delete(any())).thenReturn(responseDeleteDto);

        this.mockMvc.perform(delete("/api/v1/storage/delete")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"request\": [{\"id\": 1},{\"id\": 2}]}"))
                .andExpect(status().isOk())
                .andDo(
                        restDocs.document(
                                requestFields(
                                        fieldWithPath("request[].id").description("삭제할 유저스토리지 id")
                                ),
                                responseFields(
                                        fieldWithPath("memberEmail").description("삭제 요청한 유저 email"),
                                        fieldWithPath("response[].id").description("삭제한 유저스토리지 id"),
                                        fieldWithPath("response[].ingredientName").description("재료 이름")
                                )
                        )
                );
    }

    @Test
    @DisplayName("Update 200")
    public void update_200() throws Exception {
        ResponseUpdateDto responseUpdateDto = new ResponseUpdateDto(userStorageList.getSize());

        when(userStorageService.update(any())).thenReturn(userStorageList);

        this.mockMvc.perform(put("/api/v1/storage")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"request\": [{\"id\": 1,\"quantity\": 7,\"expiration_date\": \"2024-02-28\",\"storage_type\": \"FREEZE\"},{\"id\": 3,\"quantity\": 9,\"expiration_date\": \"2023-12-31\",\"storage_type\": \"COLD\"}]}"))
                .andExpect(status().isOk())
                .andDo(
                        restDocs.document(
                                requestFields(
                                        fieldWithPath("request[].id").description("수정할 유저스토리지 id"),
                                        fieldWithPath("request[].quantity").description("재료 양"),
                                        fieldWithPath("request[].expiration_date").description("유통 기한"),
                                        fieldWithPath("request[].storage_type").description("보관 방식")
                                ),
                                responseFields(
                                        fieldWithPath("size").description("Update 된 갯수")
                                )
                        )
                );
    }

    @Test
    @DisplayName("Get 200")
    public void get_200() throws Exception {
        ResponseGetDto responseGetDto = new ResponseGetDto("test@gmail.com", userStorages);

        when(userStorageService.get()).thenReturn(responseGetDto);

        this.mockMvc.perform(get("/api/v1/storage"))
                .andExpect(status().isOk())
                .andDo(
                        restDocs.document(
                                responseFields(
                                        fieldWithPath("memberEmail").description("요청한 유저 email"),
                                        fieldWithPath("response[].id").description("유저스토리지 id"),
                                        fieldWithPath("response[].ingredientName").description("재료 이름"),
                                        fieldWithPath("response[].ingredientImageUrl").description("재료 이미지 url"),
                                        fieldWithPath("response[].quantity").description("재료 양"),
                                        fieldWithPath("response[].expiration_date").description("유통 기한"),
                                        fieldWithPath("response[].storage_type").description("보관 방식")
                                )
                        )
                );
    }
}
