.class public Landroidx/appcompat/view/menu/rj;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/az;
.implements Landroidx/appcompat/view/menu/bz;


# instance fields
.field public final a:Landroidx/appcompat/view/menu/al0;

.field public final b:Landroid/content/Context;

.field public final c:Landroidx/appcompat/view/menu/al0;

.field public final d:Ljava/util/Set;

.field public final e:Ljava/util/concurrent/Executor;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Ljava/util/Set;Landroidx/appcompat/view/menu/al0;Ljava/util/concurrent/Executor;)V
    .locals 6

    .line 1
    new-instance v1, Landroidx/appcompat/view/menu/qj;

    invoke-direct {v1, p1, p2}, Landroidx/appcompat/view/menu/qj;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    move-object v0, p0

    move-object v2, p3

    move-object v3, p5

    move-object v4, p4

    move-object v5, p1

    invoke-direct/range {v0 .. v5}, Landroidx/appcompat/view/menu/rj;-><init>(Landroidx/appcompat/view/menu/al0;Ljava/util/Set;Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/al0;Landroid/content/Context;)V

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/al0;Ljava/util/Set;Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/al0;Landroid/content/Context;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/rj;->a:Landroidx/appcompat/view/menu/al0;

    iput-object p2, p0, Landroidx/appcompat/view/menu/rj;->d:Ljava/util/Set;

    iput-object p3, p0, Landroidx/appcompat/view/menu/rj;->e:Ljava/util/concurrent/Executor;

    iput-object p4, p0, Landroidx/appcompat/view/menu/rj;->c:Landroidx/appcompat/view/menu/al0;

    iput-object p5, p0, Landroidx/appcompat/view/menu/rj;->b:Landroid/content/Context;

    return-void
.end method

.method public static synthetic c(Landroidx/appcompat/view/menu/rj;)Ljava/lang/Void;
    .locals 0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/rj;->k()Ljava/lang/Void;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic d(Landroidx/appcompat/view/menu/rj;)Ljava/lang/String;
    .locals 0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/rj;->i()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic e(Landroid/content/Context;Ljava/lang/String;)Landroidx/appcompat/view/menu/cz;
    .locals 0

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/rj;->j(Landroid/content/Context;Ljava/lang/String;)Landroidx/appcompat/view/menu/cz;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic f(Landroidx/appcompat/view/menu/ql0;Landroidx/appcompat/view/menu/wd;)Landroidx/appcompat/view/menu/rj;
    .locals 0

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/rj;->h(Landroidx/appcompat/view/menu/ql0;Landroidx/appcompat/view/menu/wd;)Landroidx/appcompat/view/menu/rj;

    move-result-object p0

    return-object p0
.end method

.method public static g()Landroidx/appcompat/view/menu/td;
    .locals 4

    const-class v0, Landroidx/appcompat/view/menu/t7;

    const-class v1, Ljava/util/concurrent/Executor;

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/ql0;->a(Ljava/lang/Class;Ljava/lang/Class;)Landroidx/appcompat/view/menu/ql0;

    move-result-object v0

    const/4 v1, 0x2

    new-array v1, v1, [Ljava/lang/Class;

    const/4 v2, 0x0

    const-class v3, Landroidx/appcompat/view/menu/az;

    aput-object v3, v1, v2

    const/4 v2, 0x1

    const-class v3, Landroidx/appcompat/view/menu/bz;

    aput-object v3, v1, v2

    const-class v2, Landroidx/appcompat/view/menu/rj;

    invoke-static {v2, v1}, Landroidx/appcompat/view/menu/td;->f(Ljava/lang/Class;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v1

    const-class v2, Landroid/content/Context;

    invoke-static {v2}, Landroidx/appcompat/view/menu/hl;->j(Ljava/lang/Class;)Landroidx/appcompat/view/menu/hl;

    move-result-object v2

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/td$b;->b(Landroidx/appcompat/view/menu/hl;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v1

    const-class v2, Landroidx/appcompat/view/menu/sr;

    invoke-static {v2}, Landroidx/appcompat/view/menu/hl;->j(Ljava/lang/Class;)Landroidx/appcompat/view/menu/hl;

    move-result-object v2

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/td$b;->b(Landroidx/appcompat/view/menu/hl;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v1

    const-class v2, Landroidx/appcompat/view/menu/yy;

    invoke-static {v2}, Landroidx/appcompat/view/menu/hl;->l(Ljava/lang/Class;)Landroidx/appcompat/view/menu/hl;

    move-result-object v2

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/td$b;->b(Landroidx/appcompat/view/menu/hl;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v1

    const-class v2, Landroidx/appcompat/view/menu/h41;

    invoke-static {v2}, Landroidx/appcompat/view/menu/hl;->k(Ljava/lang/Class;)Landroidx/appcompat/view/menu/hl;

    move-result-object v2

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/td$b;->b(Landroidx/appcompat/view/menu/hl;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v1

    invoke-static {v0}, Landroidx/appcompat/view/menu/hl;->i(Landroidx/appcompat/view/menu/ql0;)Landroidx/appcompat/view/menu/hl;

    move-result-object v2

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/td$b;->b(Landroidx/appcompat/view/menu/hl;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v1

    new-instance v2, Landroidx/appcompat/view/menu/nj;

    invoke-direct {v2, v0}, Landroidx/appcompat/view/menu/nj;-><init>(Landroidx/appcompat/view/menu/ql0;)V

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/td$b;->f(Landroidx/appcompat/view/menu/ce;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/td$b;->d()Landroidx/appcompat/view/menu/td;

    move-result-object v0

    return-object v0
.end method

.method public static synthetic h(Landroidx/appcompat/view/menu/ql0;Landroidx/appcompat/view/menu/wd;)Landroidx/appcompat/view/menu/rj;
    .locals 7

    new-instance v6, Landroidx/appcompat/view/menu/rj;

    const-class v0, Landroid/content/Context;

    invoke-interface {p1, v0}, Landroidx/appcompat/view/menu/wd;->a(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Landroid/content/Context;

    const-class v0, Landroidx/appcompat/view/menu/sr;

    invoke-interface {p1, v0}, Landroidx/appcompat/view/menu/wd;->a(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/sr;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/sr;->n()Ljava/lang/String;

    move-result-object v2

    const-class v0, Landroidx/appcompat/view/menu/yy;

    invoke-interface {p1, v0}, Landroidx/appcompat/view/menu/wd;->c(Ljava/lang/Class;)Ljava/util/Set;

    move-result-object v3

    const-class v0, Landroidx/appcompat/view/menu/h41;

    invoke-interface {p1, v0}, Landroidx/appcompat/view/menu/wd;->d(Ljava/lang/Class;)Landroidx/appcompat/view/menu/al0;

    move-result-object v4

    invoke-interface {p1, p0}, Landroidx/appcompat/view/menu/wd;->e(Landroidx/appcompat/view/menu/ql0;)Ljava/lang/Object;

    move-result-object p0

    move-object v5, p0

    check-cast v5, Ljava/util/concurrent/Executor;

    move-object v0, v6

    invoke-direct/range {v0 .. v5}, Landroidx/appcompat/view/menu/rj;-><init>(Landroid/content/Context;Ljava/lang/String;Ljava/util/Set;Landroidx/appcompat/view/menu/al0;Ljava/util/concurrent/Executor;)V

    return-object v6
.end method

.method public static synthetic j(Landroid/content/Context;Ljava/lang/String;)Landroidx/appcompat/view/menu/cz;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/cz;

    invoke-direct {v0, p0, p1}, Landroidx/appcompat/view/menu/cz;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    return-object v0
.end method


# virtual methods
.method public a()Landroidx/appcompat/view/menu/vy0;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/rj;->b:Landroid/content/Context;

    invoke-static {v0}, Landroidx/appcompat/view/menu/k41;->a(Landroid/content/Context;)Z

    move-result v0

    xor-int/lit8 v0, v0, 0x1

    if-eqz v0, :cond_0

    const-string v0, ""

    invoke-static {v0}, Landroidx/appcompat/view/menu/fz0;->e(Ljava/lang/Object;)Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    return-object v0

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/rj;->e:Ljava/util/concurrent/Executor;

    new-instance v1, Landroidx/appcompat/view/menu/oj;

    invoke-direct {v1, p0}, Landroidx/appcompat/view/menu/oj;-><init>(Landroidx/appcompat/view/menu/rj;)V

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/fz0;->c(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;)Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    return-object v0
.end method

.method public declared-synchronized b(Ljava/lang/String;)Landroidx/appcompat/view/menu/bz$a;
    .locals 2

    monitor-enter p0

    :try_start_0
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    iget-object p1, p0, Landroidx/appcompat/view/menu/rj;->a:Landroidx/appcompat/view/menu/al0;

    invoke-interface {p1}, Landroidx/appcompat/view/menu/al0;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/cz;

    invoke-virtual {p1, v0, v1}, Landroidx/appcompat/view/menu/cz;->i(J)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/cz;->g()V

    sget-object p1, Landroidx/appcompat/view/menu/bz$a;->p:Landroidx/appcompat/view/menu/bz$a;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return-object p1

    :catchall_0
    move-exception p1

    goto :goto_0

    :cond_0
    :try_start_1
    sget-object p1, Landroidx/appcompat/view/menu/bz$a;->n:Landroidx/appcompat/view/menu/bz$a;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit p0

    return-object p1

    :goto_0
    monitor-exit p0

    throw p1
.end method

.method public final synthetic i()Ljava/lang/String;
    .locals 7

    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/rj;->a:Landroidx/appcompat/view/menu/al0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/al0;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/cz;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/cz;->c()Ljava/util/List;

    move-result-object v1

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/cz;->b()V

    new-instance v0, Lorg/json/JSONArray;

    invoke-direct {v0}, Lorg/json/JSONArray;-><init>()V

    const/4 v2, 0x0

    :goto_0
    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v3

    if-ge v2, v3, :cond_0

    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroidx/appcompat/view/menu/dz;

    new-instance v4, Lorg/json/JSONObject;

    invoke-direct {v4}, Lorg/json/JSONObject;-><init>()V

    const-string v5, "agent"

    invoke-virtual {v3}, Landroidx/appcompat/view/menu/dz;->c()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v4, v5, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    const-string v5, "dates"

    new-instance v6, Lorg/json/JSONArray;

    invoke-virtual {v3}, Landroidx/appcompat/view/menu/dz;->b()Ljava/util/List;

    move-result-object v3

    invoke-direct {v6, v3}, Lorg/json/JSONArray;-><init>(Ljava/util/Collection;)V

    invoke-virtual {v4, v5, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    invoke-virtual {v0, v4}, Lorg/json/JSONArray;->put(Ljava/lang/Object;)Lorg/json/JSONArray;

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_4

    :cond_0
    new-instance v1, Lorg/json/JSONObject;

    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    const-string v2, "heartbeats"

    invoke-virtual {v1, v2, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    const-string v0, "version"

    const-string v2, "2"

    invoke-virtual {v1, v0, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    new-instance v0, Ljava/io/ByteArrayOutputStream;

    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    new-instance v2, Landroid/util/Base64OutputStream;

    const/16 v3, 0xb

    invoke-direct {v2, v0, v3}, Landroid/util/Base64OutputStream;-><init>(Ljava/io/OutputStream;I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :try_start_1
    new-instance v3, Ljava/util/zip/GZIPOutputStream;

    invoke-direct {v3, v2}, Ljava/util/zip/GZIPOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :try_start_2
    invoke-virtual {v1}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object v1

    const-string v4, "UTF-8"

    invoke-virtual {v1, v4}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    move-result-object v1

    invoke-virtual {v3, v1}, Ljava/io/OutputStream;->write([B)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    :try_start_3
    invoke-virtual {v3}, Ljava/io/OutputStream;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    :try_start_4
    invoke-virtual {v2}, Landroid/util/Base64OutputStream;->close()V

    const-string v1, "UTF-8"

    invoke-virtual {v0, v1}, Ljava/io/ByteArrayOutputStream;->toString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    return-object v0

    :catchall_1
    move-exception v0

    goto :goto_2

    :catchall_2
    move-exception v0

    :try_start_5
    invoke-virtual {v3}, Ljava/io/OutputStream;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    goto :goto_1

    :catchall_3
    move-exception v1

    :try_start_6
    invoke-virtual {v0, v1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_1
    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    :goto_2
    :try_start_7
    invoke-virtual {v2}, Landroid/util/Base64OutputStream;->close()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_4

    goto :goto_3

    :catchall_4
    move-exception v1

    :try_start_8
    invoke-virtual {v0, v1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_3
    throw v0

    :goto_4
    monitor-exit p0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    throw v0
.end method

.method public final synthetic k()Ljava/lang/Void;
    .locals 4

    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/rj;->a:Landroidx/appcompat/view/menu/al0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/al0;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/cz;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v1

    iget-object v3, p0, Landroidx/appcompat/view/menu/rj;->c:Landroidx/appcompat/view/menu/al0;

    invoke-interface {v3}, Landroidx/appcompat/view/menu/al0;->get()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroidx/appcompat/view/menu/h41;

    invoke-interface {v3}, Landroidx/appcompat/view/menu/h41;->a()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0, v1, v2, v3}, Landroidx/appcompat/view/menu/cz;->k(JLjava/lang/String;)V

    monitor-exit p0

    const/4 v0, 0x0

    return-object v0

    :catchall_0
    move-exception v0

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public l()Landroidx/appcompat/view/menu/vy0;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/rj;->d:Ljava/util/Set;

    invoke-interface {v0}, Ljava/util/Set;->size()I

    move-result v0

    const/4 v1, 0x0

    if-gtz v0, :cond_0

    invoke-static {v1}, Landroidx/appcompat/view/menu/fz0;->e(Ljava/lang/Object;)Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    return-object v0

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/rj;->b:Landroid/content/Context;

    invoke-static {v0}, Landroidx/appcompat/view/menu/k41;->a(Landroid/content/Context;)Z

    move-result v0

    xor-int/lit8 v0, v0, 0x1

    if-eqz v0, :cond_1

    invoke-static {v1}, Landroidx/appcompat/view/menu/fz0;->e(Ljava/lang/Object;)Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    return-object v0

    :cond_1
    iget-object v0, p0, Landroidx/appcompat/view/menu/rj;->e:Ljava/util/concurrent/Executor;

    new-instance v1, Landroidx/appcompat/view/menu/pj;

    invoke-direct {v1, p0}, Landroidx/appcompat/view/menu/pj;-><init>(Landroidx/appcompat/view/menu/rj;)V

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/fz0;->c(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;)Landroidx/appcompat/view/menu/vy0;

    move-result-object v0

    return-object v0
.end method
