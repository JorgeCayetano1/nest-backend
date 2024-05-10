import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import * as bcryptjs from 'bcryptjs';

import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { User } from './entities/user.entity';
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from './interfaces/jwt-payload';
import { JwtService } from '@nestjs/jwt';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createUserDto;
      const newUser = new this.userModel({
        ...userData,
        password: bcryptjs.hashSync(password, 10),
      });

      await newUser.save();
      const { password: _, ...user } = newUser.toJSON();

      return user;
    } catch (error) {
      console.log(error);
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists!`);
      }
      throw new InternalServerErrorException('Error creating user!');
    }
  }

  async register(createUserDto: CreateUserDto): Promise<LoginResponse> {
    const { password: _, ...user } = await this.create(createUserDto);
    const findUser = await this.userModel.findOne({ email: user.email });
    return {
      user,
      token: this.getJwtToken({ id: findUser.id }),
    };
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials - email');
    }
    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Invalid credentials - password');
    }

    const { password: _, ...result } = user.toJSON();
    return {
      user: result,
      token: this.getJwtToken({ id: user.id }),
    };
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string): Promise<User> {
    const user = await this.userModel.findById(id);
    const { password: _, ...rest } = user.toJSON();
    return rest;
  }

  // async checkToken(token: string): Promise<LoginResponse> {
  //   try {
  //     const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
  //       secret: process.env.JWT_SEED,
  //     });
  //     const user = await this.findUserById(payload.id);
  //     return {
  //       user,
  //       token,
  //     };
  //   } catch (error) {
  //     throw new UnauthorizedException('Invalid token');
  //   }
  // }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
