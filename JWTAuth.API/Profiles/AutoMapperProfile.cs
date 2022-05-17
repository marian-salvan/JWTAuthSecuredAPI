﻿using AutoMapper;
using JWTAuthSecured.Core.ApiRequests;
using JWTAuthSecured.Data.Entities;

namespace JWTAuthSecuredAPI.Profiles
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            CreateMap<RegisterRequestModel, UserEntity>()
                .ForMember(destination => destination.UserName, opt => opt.MapFrom(x => x.Username));
        }
    }
}
