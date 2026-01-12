.class public final Landroidx/appcompat/view/menu/ra$a;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/ra;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# static fields
.field public static final synthetic a:Landroidx/appcompat/view/menu/ra$a;

.field public static final b:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Landroidx/appcompat/view/menu/ra$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/ra$a;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/ra$a;->a:Landroidx/appcompat/view/menu/ra$a;

    const/4 v0, 0x1

    const v1, 0x7ffffffe

    const-string v2, "kotlinx.coroutines.channels.defaultBuffer"

    const/16 v3, 0x40

    invoke-static {v2, v3, v0, v1}, Landroidx/appcompat/view/menu/py0;->b(Ljava/lang/String;III)I

    move-result v0

    sput v0, Landroidx/appcompat/view/menu/ra$a;->b:I

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final a()I
    .locals 1

    sget v0, Landroidx/appcompat/view/menu/ra$a;->b:I

    return v0
.end method
