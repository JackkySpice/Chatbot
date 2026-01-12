.class public Landroidx/appcompat/view/menu/a2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/z1;


# static fields
.field public static volatile c:Landroidx/appcompat/view/menu/z1;


# instance fields
.field public final a:Landroidx/appcompat/view/menu/s3;

.field public final b:Ljava/util/Map;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/s3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Landroidx/appcompat/view/menu/a2;->a:Landroidx/appcompat/view/menu/s3;

    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/a2;->b:Ljava/util/Map;

    return-void
.end method

.method public static c(Landroidx/appcompat/view/menu/sr;Landroid/content/Context;Landroidx/appcompat/view/menu/xx0;)Landroidx/appcompat/view/menu/z1;
    .locals 5

    invoke-static {p0}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-static {p1}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-static {p2}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Landroidx/appcompat/view/menu/a2;->c:Landroidx/appcompat/view/menu/z1;

    if-nez v0, :cond_2

    const-class v0, Landroidx/appcompat/view/menu/a2;

    monitor-enter v0

    :try_start_0
    sget-object v1, Landroidx/appcompat/view/menu/a2;->c:Landroidx/appcompat/view/menu/z1;

    if-nez v1, :cond_1

    new-instance v1, Landroid/os/Bundle;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Landroid/os/Bundle;-><init>(I)V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->t()Z

    move-result v2

    if-eqz v2, :cond_0

    const-class v2, Landroidx/appcompat/view/menu/vi;

    sget-object v3, Landroidx/appcompat/view/menu/fe1;->m:Landroidx/appcompat/view/menu/fe1;

    sget-object v4, Landroidx/appcompat/view/menu/mh1;->a:Landroidx/appcompat/view/menu/mh1;

    invoke-interface {p2, v2, v3, v4}, Landroidx/appcompat/view/menu/xx0;->a(Ljava/lang/Class;Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/yo;)V

    const-string p2, "dataCollectionDefaultEnabled"

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->s()Z

    move-result p0

    invoke-virtual {v1, p2, p0}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_0
    :goto_0
    new-instance p0, Landroidx/appcompat/view/menu/a2;

    const/4 p2, 0x0

    invoke-static {p1, p2, p2, p2, v1}, Landroidx/appcompat/view/menu/in1;->f(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroidx/appcompat/view/menu/in1;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/in1;->u()Landroidx/appcompat/view/menu/s3;

    move-result-object p1

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/a2;-><init>(Landroidx/appcompat/view/menu/s3;)V

    sput-object p0, Landroidx/appcompat/view/menu/a2;->c:Landroidx/appcompat/view/menu/z1;

    :cond_1
    monitor-exit v0

    goto :goto_2

    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0

    :cond_2
    :goto_2
    sget-object p0, Landroidx/appcompat/view/menu/a2;->c:Landroidx/appcompat/view/menu/z1;

    return-object p0
.end method

.method public static synthetic d(Landroidx/appcompat/view/menu/uo;)V
    .locals 0

    const/4 p0, 0x0

    throw p0
.end method


# virtual methods
.method public a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V
    .locals 1

    invoke-static {p1}, Landroidx/appcompat/view/menu/nh1;->e(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    invoke-static {p1, p2}, Landroidx/appcompat/view/menu/nh1;->c(Ljava/lang/String;Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :cond_1

    return-void

    :cond_1
    iget-object v0, p0, Landroidx/appcompat/view/menu/a2;->a:Landroidx/appcompat/view/menu/s3;

    invoke-virtual {v0, p1, p2, p3}, Landroidx/appcompat/view/menu/s3;->b(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    return-void
.end method

.method public b(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 1

    if-nez p3, :cond_0

    new-instance p3, Landroid/os/Bundle;

    invoke-direct {p3}, Landroid/os/Bundle;-><init>()V

    :cond_0
    invoke-static {p1}, Landroidx/appcompat/view/menu/nh1;->e(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :cond_1

    return-void

    :cond_1
    invoke-static {p2, p3}, Landroidx/appcompat/view/menu/nh1;->b(Ljava/lang/String;Landroid/os/Bundle;)Z

    move-result v0

    if-nez v0, :cond_2

    return-void

    :cond_2
    invoke-static {p1, p2, p3}, Landroidx/appcompat/view/menu/nh1;->d(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Z

    move-result v0

    if-nez v0, :cond_3

    return-void

    :cond_3
    invoke-static {p1, p2, p3}, Landroidx/appcompat/view/menu/nh1;->a(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/a2;->a:Landroidx/appcompat/view/menu/s3;

    invoke-virtual {v0, p1, p2, p3}, Landroidx/appcompat/view/menu/s3;->a(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    return-void
.end method
