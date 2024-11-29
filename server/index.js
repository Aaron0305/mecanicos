const oracledb = require("oracledb");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());
app.use(cors());

const dbConfig = {
  user: "admin",
  password: "AARtre78",
  connectString: "localhost:1521/XE",
};

// Función para cifrar contraseñas
const encryptPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
};

// Ruta de login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Email y contraseña son requeridos." });
  }

  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);

    const result = await connection.execute(
      `SELECT TIPO_USUARIO, PASSWORD 
       FROM USUARIOS 
       WHERE EMAIL = :email`,
      { email }
    );

    if (result.rows.length > 0) {
      const [tipoUsuario, storedPassword] = result.rows[0];

      const isMatch = await bcrypt.compare(password, storedPassword);
      if (isMatch) {
        res.json({ success: true, role: tipoUsuario });
      } else {
        res.status(401).json({ success: false, message: "Credenciales incorrectas" });
      }
    } else {
      res.status(401).json({ success: false, message: "Usuario no encontrado" });
    }
  } catch (err) {
    console.error("Error en la base de datos:", err);
    res.status(500).json({ success: false, message: "Error del servidor", error: err.message });
  } finally {
    if (connection) await connection.close();
  }
});

// Ruta de registro
app.post("/register", async (req, res) => {
  const { email, password, tipo_usuario, nombre, estado, municipio, ciudad, colonia, calle, numero } = req.body;

  if (!email || !password || !tipo_usuario || !nombre) {
    return res.status(400).json({ success: false, message: "Todos los campos obligatorios son requeridos." });
  }

  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);

    const emailExists = await connection.execute(
      `SELECT COUNT(*) FROM USUARIOS WHERE EMAIL = :email`,
      { email }
    );

    if (emailExists.rows[0][0] > 0) {
      return res.status(400).json({ success: false, message: "El correo ya está registrado." });
    }

    const hashedPassword = await encryptPassword(password);

    const nextIdResult = await connection.execute(
      `SELECT NVL(MAX(ID), 0) + 1 FROM USUARIOS`
    );
    const nextId = nextIdResult.rows[0][0];

    await connection.execute(
      `INSERT INTO USUARIOS (
        ID, EMAIL, PASSWORD, TIPO_USUARIO, NOMBRE, ESTADO, MUNICIPIO, CIUDAD, 
        COLONIA, CALLE, NUMERO, FECHA_REGISTRO
      ) VALUES (
        :id, :email, :password, :tipo_usuario, :nombre, :estado, :municipio, 
        :ciudad, :colonia, :calle, :numero, SYSTIMESTAMP
      )`,
      {
        id: nextId,
        email,
        password: hashedPassword,
        tipo_usuario,
        nombre,
        estado: estado || null,
        municipio: municipio || null,
        ciudad: ciudad || null,
        colonia: colonia || null,
        calle: calle || null,
        numero: numero || null,
      },
      { autoCommit: true }
    );

    res.json({ success: true, message: "Registro exitoso" });
  } catch (err) {
    console.error("Error en la base de datos:", err);
    res.status(500).json({ success: false, message: "Error del servidor", error: err.message });
  } finally {
    if (connection) await connection.close();
  }
});

// Ruta de perfil profesional
app.post("/perfil-profesional", async (req, res) => {
  const { email, especialidades, descripcion, experiencia, certificaciones, horarioDisponible, areaServicio } = req.body;

  if (!email || !especialidades || !descripcion || !experiencia) {
    return res.status(400).json({ success: false, message: "Campos obligatorios faltantes." });
  }

  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);

    const userResult = await connection.execute(
      `SELECT ID FROM USUARIOS WHERE EMAIL = :email`,
      { email }
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: "Usuario no encontrado." });
    }

    const usuarioId = userResult.rows[0][0];

    const perfilResult = await connection.execute(
      `SELECT COUNT(*) FROM PERFILPROFESIONAL WHERE ID_USUARIO = :usuarioId`,
      { usuarioId }
    );

    const existePerfil = perfilResult.rows[0][0] > 0;

    if (existePerfil) {
      await connection.execute(
        `UPDATE PERFILPROFESIONAL SET
          ESPECIALIDADES = :especialidades,
          DESCRIPCIÓNPROFESIONAL = :descripcion,
          EXPERIENCIA = :experiencia,
          CERTIFICACIONES = :certificaciones,
          HORARIODISPONIBLE = :horarioDisponible,
          ÁREADESERVICIO = :areaServicio
         WHERE ID_USUARIO = :usuarioId`,
        {
          especialidades,
          descripcion,
          experiencia,
          certificaciones: certificaciones || null,
          horarioDisponible: horarioDisponible || null,
          areaServicio: areaServicio || null,
          usuarioId,
        },
        { autoCommit: true }
      );
      res.json({ success: true, message: "Perfil actualizado correctamente." });
    } else {
      const nextIdResult = await connection.execute(`SELECT PERFILPROFESIONAL_SEQ.NEXTVAL FROM DUAL`);
      const nextId = nextIdResult.rows[0][0];

      await connection.execute(
        `INSERT INTO PERFILPROFESIONAL (
          ID, ESPECIALIDADES, DESCRIPCIÓNPROFESIONAL, EXPERIENCIA, CERTIFICACIONES, 
          HORARIODISPONIBLE, ÁREADESERVICIO, ID_USUARIO
        ) VALUES (
          :id, :especialidades, :descripcion, :experiencia, :certificaciones, 
          :horarioDisponible, :areaServicio, :usuarioId
        )`,
        {
          id: nextId,
          especialidades,
          descripcion,
          experiencia,
          certificaciones: certificaciones || null,
          horarioDisponible: horarioDisponible || null,
          areaServicio: areaServicio || null,
          usuarioId,
        },
        { autoCommit: true }
      );
      res.json({ success: true, message: "Perfil registrado correctamente." });
    }
  } catch (err) {
    console.error("Error en la base de datos:", err);
    res.status(500).json({ success: false, message: "Error del servidor", error: err.message });
  } finally {
    if (connection) await connection.close();
  }
});

// Iniciar servidor
const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
