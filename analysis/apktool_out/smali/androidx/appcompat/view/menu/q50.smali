.class public final Landroidx/appcompat/view/menu/q50;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/uq;


# static fields
.field public static final b:Landroidx/appcompat/view/menu/q50;


# instance fields
.field public final a:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/q50;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/q50;-><init>(Ljava/lang/Object;)V

    sput-object v0, Landroidx/appcompat/view/menu/q50;->b:Landroidx/appcompat/view/menu/q50;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/q50;->a:Ljava/lang/Object;

    return-void
.end method

.method public static a(Ljava/lang/Object;)Landroidx/appcompat/view/menu/uq;
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/q50;

    const-string v1, "instance cannot be null"

    invoke-static {p0, v1}, Landroidx/appcompat/view/menu/hj0;->c(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p0

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/q50;-><init>(Ljava/lang/Object;)V

    return-object v0
.end method


# virtual methods
.method public get()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/q50;->a:Ljava/lang/Object;

    return-object v0
.end method
