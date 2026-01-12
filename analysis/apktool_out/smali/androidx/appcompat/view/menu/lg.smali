.class public abstract Landroidx/appcompat/view/menu/lg;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static a(Landroid/content/Context;)V
    .locals 4

    const/4 v0, 0x0

    move v1, v0

    :cond_0
    :try_start_0
    instance-of v2, p0, Landroid/content/ContextWrapper;

    if-eqz v2, :cond_1

    check-cast p0, Landroid/content/ContextWrapper;

    invoke-virtual {p0}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    move-result-object p0

    add-int/lit8 v1, v1, 0x1

    const/16 v2, 0xa

    if-lt v1, v2, :cond_0

    return-void

    :catch_0
    move-exception p0

    goto :goto_1

    :cond_1
    sget-object v1, Landroidx/appcompat/view/menu/sg;->d:Landroidx/appcompat/view/menu/co0$b;

    const/4 v2, 0x0

    invoke-virtual {v1, p0, v2}, Landroidx/appcompat/view/menu/co0$b;->d(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :try_start_1
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v1

    :try_start_2
    invoke-virtual {v1}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_0
    sget-object v1, Landroidx/appcompat/view/menu/sg;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->o()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, p0, v2}, Landroidx/appcompat/view/menu/co0$b;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Landroidx/appcompat/view/menu/tg;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->o()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, p0, v2}, Landroidx/appcompat/view/menu/co0$b;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Landroidx/appcompat/view/menu/ig;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {p0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v2

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->o()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v2, v3}, Landroidx/appcompat/view/menu/co0$b;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-static {}, Landroidx/appcompat/view/menu/x8;->h()Z

    move-result v1

    if-eqz v1, :cond_2

    sget-object v1, Landroidx/appcompat/view/menu/sg;->f:Landroidx/appcompat/view/menu/co0$d;

    new-array v0, v0, [Ljava/lang/Object;

    invoke-virtual {v1, p0, v0}, Landroidx/appcompat/view/menu/co0$d;->a(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->J2()I

    move-result v0

    invoke-static {p0, v0}, Landroidx/appcompat/view/menu/lg;->b(Ljava/lang/Object;I)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    goto :goto_2

    :goto_1
    invoke-virtual {p0}, Ljava/lang/Throwable;->printStackTrace()V

    :cond_2
    :goto_2
    return-void
.end method

.method public static b(Ljava/lang/Object;I)V
    .locals 3

    if-eqz p0, :cond_0

    sget-object v0, Landroidx/appcompat/view/menu/e5;->b:Landroidx/appcompat/view/menu/co0$b;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p0}, Landroidx/appcompat/view/menu/co0$b;->b(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Landroidx/appcompat/view/menu/f5;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->o()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v0, v2}, Landroidx/appcompat/view/menu/co0$b;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Landroidx/appcompat/view/menu/f5;->c:Landroidx/appcompat/view/menu/co0$b;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v1, v0, v2}, Landroidx/appcompat/view/menu/co0$b;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Landroidx/appcompat/view/menu/e5;->c:Landroidx/appcompat/view/menu/co0$d;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    invoke-virtual {v0, p0, v1}, Landroidx/appcompat/view/menu/co0$d;->a(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/lg;->b(Ljava/lang/Object;I)V

    :cond_0
    return-void
.end method
