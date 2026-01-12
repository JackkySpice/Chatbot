.class public final Landroidx/appcompat/view/menu/mq;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Landroidx/appcompat/view/menu/mq;

.field public static final b:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/mq;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/mq;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/mq;->a:Landroidx/appcompat/view/menu/mq;

    const-class v0, Landroidx/appcompat/view/menu/mq;

    invoke-static {v0}, Landroidx/appcompat/view/menu/zn0;->b(Ljava/lang/Class;)Landroidx/appcompat/view/menu/h70;

    move-result-object v0

    invoke-interface {v0}, Landroidx/appcompat/view/menu/h70;->c()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/mq;->b:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final a()I
    .locals 2

    const/4 v0, 0x0

    :try_start_0
    invoke-static {}, Landroidx/window/extensions/WindowExtensionsProvider;->getWindowExtensions()Landroidx/window/extensions/WindowExtensions;

    move-result-object v1

    invoke-interface {v1}, Landroidx/window/extensions/WindowExtensions;->getVendorApiLevel()I

    move-result v0
    :try_end_0
    .catch Ljava/lang/NoClassDefFoundError; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    sget-object v1, Landroidx/appcompat/view/menu/y8;->a:Landroidx/appcompat/view/menu/y8;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/y8;->a()Landroidx/appcompat/view/menu/a51;

    sget-object v1, Landroidx/appcompat/view/menu/a51;->m:Landroidx/appcompat/view/menu/a51;

    goto :goto_0

    :catch_1
    sget-object v1, Landroidx/appcompat/view/menu/y8;->a:Landroidx/appcompat/view/menu/y8;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/y8;->a()Landroidx/appcompat/view/menu/a51;

    sget-object v1, Landroidx/appcompat/view/menu/a51;->m:Landroidx/appcompat/view/menu/a51;

    :goto_0
    return v0
.end method
