
import express, { Router } from 'express';
import cors from 'cors';
import db from './src/db.js';


const port = 3001;
const app = express();
const router = Router();
const userRouter = Router();
const challengeRouter = Router();
app.use(express.json());
app.use(cors());


/**
 * Users
 */
userRouter.get('/', (req, res) => {
    try {
        res.status(200).json(db.getUsers());
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

userRouter.get('/:id', (req, res) => {
    try {
        res.status(200).json(db.getUserByCredentialId(req.params.id));
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

userRouter.post('/', (req, res) => {
    try {
        const newUser = req.body;
        const user = {
            credential_id: newUser.credential_id,
            username: newUser.username,
            public_key: newUser.public_key,
        }
        const response = db.addUser(user);
        res.status(201).json(response);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});


/**
 * Challanges
 */

challengeRouter.get('/', (req, res) => {
    try {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        res.status(200).json(Array.from(challenge));
    } catch (error) {
        res.status(400).json({ error: err.message });
    } 
})

router.use('/users', userRouter);
router.use('/challanges', challengeRouter);
app.use('/api/v1', router);

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});