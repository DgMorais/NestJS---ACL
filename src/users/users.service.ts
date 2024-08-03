import { Injectable, Logger, NotFoundException, BadRequestException, Inject, forwardRef } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcrypt';
import { AuthService } from 'src/auth/auth.service';

@Injectable()
export class UsersService {
    private readonly logger = new Logger(UsersService.name);

    constructor(
        @InjectRepository(User)
        private readonly usersRepository: Repository<User>,
        @Inject(forwardRef(() => AuthService))
        private authService: AuthService,
    ) { }

    async create(createUserDto: CreateUserDto): Promise<Omit<User, 'password'>> {
        try {
            const user = this.usersRepository.create(createUserDto);
            const savedUser = await this.usersRepository.save(user);
            const { password, ...result } = savedUser;
            return result;
        } catch (error) {
            this.logger.error(`Error creating user: ${error.message}`);
            throw new BadRequestException('Error creating user');
        }
    }

    async findAll(): Promise<Omit<User, 'password'>[]> {
        const users = await this.usersRepository.find({ relations: ['roles', 'groups'] });
        return users.map(({ password, ...result }) => result);
    }

    async findOne(id: number): Promise<Omit<User, 'password'>> {
        const user = await this.usersRepository.findOne({ where: { id }, relations: ['roles', 'groups'] });
        if (!user) {
            throw new NotFoundException('Usuário não encontrado');
        }
        const { password, ...result } = user;
        return result;
    }

    async update(id: number, updateUserDto: UpdateUserDto): Promise<Omit<User, 'password'>> {
        const user = await this.findOne(id); // Verify user exists
        if (updateUserDto.password) {
            updateUserDto.password = await bcrypt.hash(updateUserDto.password, 10);
        }
        await this.usersRepository.update(id, updateUserDto);
        return this.findOne(id);
    }

    async remove(id: number): Promise<void> {
        const user = await this.findOne(id); // Verify user exists
        await this.usersRepository.delete(id);
    }

    async findOneByEmail(email: string): Promise<Omit<User, 'password'>> {
        const user = await this.usersRepository.findOne({ where: { email }, relations: ['roles', 'groups'] });
        if (!user) {
            throw new NotFoundException('Usuário não encontrado');
        }
        const { password, ...result } = user;
        return result;
    }

    async findOneByEmailWithPassword(email: string): Promise<User> {
        const user = await this.usersRepository.findOne({ where: { email } });
        if (!user) {
            throw new NotFoundException('Usuário não encontrado');
        }
        return user;
    }
}
