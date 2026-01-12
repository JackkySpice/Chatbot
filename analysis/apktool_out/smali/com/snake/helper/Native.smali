.class public Lcom/snake/helper/Native;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static native ac(Ljava/lang/Object;Ljava/lang/Object;)V
    .annotation build Landroidx/annotation/Keep;
    .end annotation
.end method

.method public static native aior(Ljava/lang/String;Ljava/lang/String;)V
    .annotation build Landroidx/annotation/Keep;
    .end annotation
.end method

.method public static native awl(Ljava/lang/String;)V
    .annotation build Landroidx/annotation/Keep;
    .end annotation
.end method

.method public static native djp(I)[B
    .annotation build Landroidx/annotation/Keep;
    .end annotation
.end method

.method public static native eio()V
    .annotation build Landroidx/annotation/Keep;
    .end annotation
.end method

.method public static gcuid(I)I
    .locals 1
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    if-lez p0, :cond_0

    const/16 v0, 0x2710

    if-ge p0, v0, :cond_0

    return p0

    :cond_0
    const/16 v0, 0x4e1f

    if-le p0, v0, :cond_1

    return p0

    :cond_1
    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->p()I

    move-result v0

    if-ne p0, v0, :cond_3

    invoke-static {}, Landroid/os/Binder;->getCallingPid()I

    move-result p0

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->u()Landroidx/appcompat/view/menu/mv0;

    move-result-object v0

    invoke-virtual {v0, p0}, Landroidx/appcompat/view/menu/mv0;->r(I)I

    move-result p0

    const/4 v0, -0x1

    if-eq p0, v0, :cond_2

    return p0

    :cond_2
    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->K2()I

    move-result p0

    :cond_3
    return p0
.end method

.method public static getApplicationInfo(Landroid/content/Context;Ljava/lang/String;)Landroid/content/pm/ApplicationInfo;
    .locals 1
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object p0

    const/4 v0, 0x0

    invoke-virtual {p0, p1, v0}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static native i(I)V
    .annotation build Landroidx/annotation/Keep;
    .end annotation
.end method

.method public static native ic(Landroid/content/Context;)V
    .annotation build Landroidx/annotation/Keep;
    .end annotation
.end method

.method public static il(Ljava/io/File;)Ljava/io/File;
    .locals 1
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 2
    invoke-static {}, Landroidx/appcompat/view/menu/b20;->d()Landroidx/appcompat/view/menu/b20;

    move-result-object v0

    invoke-virtual {v0, p0}, Landroidx/appcompat/view/menu/b20;->g(Ljava/io/File;)Ljava/io/File;

    move-result-object p0

    return-object p0
.end method

.method public static il(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 1
    invoke-static {}, Landroidx/appcompat/view/menu/b20;->d()Landroidx/appcompat/view/menu/b20;

    move-result-object v0

    invoke-virtual {v0, p0}, Landroidx/appcompat/view/menu/b20;->h(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static native ilil(Ljava/lang/String;)Ljava/lang/String;
    .annotation build Landroidx/annotation/Keep;
    .end annotation
.end method

.method public static native pjowqpxe(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .annotation build Landroidx/annotation/Keep;
    .end annotation
.end method

.method public static native update(Ljava/lang/Object;Ljava/lang/reflect/Method;)V
    .annotation build Landroidx/annotation/Keep;
    .end annotation
.end method
