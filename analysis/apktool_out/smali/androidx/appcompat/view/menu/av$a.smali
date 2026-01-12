.class public Landroidx/appcompat/view/menu/av$a;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/av;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "a"
.end annotation


# instance fields
.field public final a:I

.field public final b:[Landroidx/appcompat/view/menu/av$b;


# direct methods
.method public constructor <init>(I[Landroidx/appcompat/view/menu/av$b;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Landroidx/appcompat/view/menu/av$a;->a:I

    iput-object p2, p0, Landroidx/appcompat/view/menu/av$a;->b:[Landroidx/appcompat/view/menu/av$b;

    return-void
.end method

.method public static a(I[Landroidx/appcompat/view/menu/av$b;)Landroidx/appcompat/view/menu/av$a;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/av$a;

    invoke-direct {v0, p0, p1}, Landroidx/appcompat/view/menu/av$a;-><init>(I[Landroidx/appcompat/view/menu/av$b;)V

    return-object v0
.end method


# virtual methods
.method public b()[Landroidx/appcompat/view/menu/av$b;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/av$a;->b:[Landroidx/appcompat/view/menu/av$b;

    return-object v0
.end method

.method public c()I
    .locals 1

    iget v0, p0, Landroidx/appcompat/view/menu/av$a;->a:I

    return v0
.end method
